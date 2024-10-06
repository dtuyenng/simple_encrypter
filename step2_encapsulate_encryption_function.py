# import base64
# from cryptography.fernet import Fernet, InvalidToken
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from pathlib import Path
#
# # convert password and salt to binary
# password = b"insertpasswordhere"
# salt = b"insertsalthere"
#
# kdf = PBKDF2HMAC(
#     algorithm = hashes.SHA256(),
#     length = 32,
#     salt =  salt,
#     iterations = 100_000,
# )
# # Derive the key using the password and the salt
# key = base64.urlsafe_b64encode(kdf.derive(password))
#
# # Initializing our encryption method using the key
# fernet = Fernet(key)
#
# def encrypt (data: bytes) -> bytes:
#     return fernet.encrypt(data)
#
# def encrypt(message: bytes) -> bytes:
#     return fernet.encrypt(message)
#
# def decrypt(message:bytes) -> bytes:
#     try:
#         decrypted_message = fernet.decrypt(message)
#         return decrypted_message
#     except InvalidToken:
#         print("Decryption failed. The password might be incorrect or the data might be corrupted.")
#     except Exception as e:
#         print(f"An error occurred: {e}")