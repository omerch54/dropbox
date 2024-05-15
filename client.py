##
## client.py - Dropbox client implementation
##

## **Support code libraries**
import pickle
import support.crypto as crypto  # Our crypto library
import support.util as util  # Various helper functions
from support.dataserver import dataserver, memloc
from support.keyserver import keyserver

def s_addr(s):
    return memloc.MakeFromBytes(crypto.Hash(s.encode("utf-8"))[:16])

def derive_user_key(password, salt):
    return crypto.PasswordKDF(password, salt, 16)

def encrypt_data(data, key):
    iv = crypto.SecureRandom(16)
    encrypted = crypto.SymmetricEncrypt(key, iv, data)
    return iv + encrypted  # Prepend IV for decryption

def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]  # Extract the IV
    encrypted_data = encrypted_data[16:]
    return crypto.SymmetricDecrypt(key, iv, encrypted_data)

class User:
    def __init__(self, username, enc_key, dec_key) -> None:
        self.username = username
        self.enc_key = enc_key
        self.dec_key = dec_key

    def upload_file(self, filename: str, data: bytes) -> None:
        file_key = crypto.SecureRandom(16)
        encrypted_file_data = encrypt_data(data, file_key)
        file_loc = memloc.Make()

        dataserver.Set(file_loc, encrypted_file_data)

        encrypted_file_key = crypto.AsymmetricEncrypt(self.enc_key, file_key)
        # Serialize the tuple
        serialized_data = pickle.dumps((encrypted_file_key, file_loc))
        dataserver.Set(s_addr(f"{self.username}_{filename}"), serialized_data)

    def download_file(self, filename: str) -> bytes:
        serialized_data = dataserver.Get(s_addr(f"{self.username}_{filename}"))
        encrypted_file_key, file_loc = pickle.loads(serialized_data)

        file_key = crypto.AsymmetricDecrypt(self.dec_key, encrypted_file_key)
        encrypted_file_data = dataserver.Get(file_loc)
        return decrypt_data(encrypted_file_data, file_key)

    def append_file(self, filename: str, data: bytes) -> None:
        existing_data = self.download_file(filename)
        updated_data = existing_data + data
        self.upload_file(filename, updated_data)

    def share_file(self, filename: str, recipient: str) -> None:
        shared_key = crypto.SecureRandom(16)
        file_data = self.download_file(filename)
        encrypted_file_data = encrypt_data(file_data, shared_key)
        file_loc = memloc.Make()

        dataserver.Set(file_loc, encrypted_file_data)

        encrypted_shared_key_owner = crypto.AsymmetricEncrypt(self.enc_key, shared_key)
        recipient_enc_key = keyserver.Get(recipient)
        encrypted_shared_key_recipient = crypto.AsymmetricEncrypt(recipient_enc_key, shared_key)

        # Serialize sharing info
        serialized_share_info = pickle.dumps((encrypted_shared_key_owner, encrypted_shared_key_recipient, file_loc))
        dataserver.Set(s_addr(f"{self.username}_{recipient}_{filename}"), serialized_share_info)

    def receive_file(self, filename: str, sender: str) -> bytes:
        serialized_share_info = dataserver.Get(s_addr(f"{sender}_{self.username}_{filename}"))
        encrypted_shared_keys, file_loc = pickle.loads(serialized_share_info)

        shared_key = crypto.AsymmetricDecrypt(self.dec_key, encrypted_shared_keys[1])
        encrypted_file_data = dataserver.Get(file_loc)
        return decrypt_data(encrypted_file_data, shared_key)

    def revoke_file(self, filename: str, old_recipient: str) -> None:
        file_data = self.download_file(filename)
        new_key = crypto.SecureRandom(16)
        encrypted_file_data = encrypt_data(file_data, new_key)
        file_loc = memloc.Make()

        dataserver.Set(file_loc, encrypted_file_data)

        encrypted_new_key = crypto.AsymmetricEncrypt(self.enc_key, new_key)
        serialized_new_key = pickle.dumps((encrypted_new_key, file_loc))
        dataserver.Set(s_addr(f"{self.username}_{filename}"), serialized_new_key)

        dataserver.Delete(s_addr(f"{self.username}_{old_recipient}_{filename}"))

def create_user(username: str, password: str) -> User:
    salt = crypto.SecureRandom(16)
    user_key = derive_user_key(password, salt)

    enc_key, dec_key = crypto.AsymmetricKeyGen()

    encrypted_dec_key = encrypt_data(dec_key.serialize(), user_key)  # Assuming serialize() method

    user_salt_loc = memloc.Make()
    user_enc_key_loc = memloc.Make()
    user_dec_key_loc = memloc.Make()

    dataserver.Set(user_salt_loc, salt)
    dataserver.Set(user_enc_key_loc, enc_key.serialize())  # Assuming serialize() method
    dataserver.Set(user_dec_key_loc, encrypted_dec_key)

    keyserver.Set(username, enc_key.serialize())  # Assuming serialize() method

    return User(username, enc_key, dec_key)

def authenticate_user(username: str, password: str) -> User:
    enc_key_bytes = keyserver.Get(username)
    enc_key = crypto.AsymmetricEncryptKey.deserialize(enc_key_bytes)  # Assuming deserialize() method

    user_salt_loc, user_enc_key_loc, user_dec_key_loc, _ = create_user(username, password)

    salt = dataserver.Get(user_salt_loc)
    user_key = derive_user_key(password, salt)

    encrypted_dec_key = dataserver.Get(user_dec_key_loc)
    dec_key_bytes = decrypt_data(encrypted_dec_key, user_key)
    dec_key = crypto.AsymmetricDecryptKey.deserialize(dec_key_bytes)  # Assuming deserialize() method

    return User(username, enc_key, dec_key)