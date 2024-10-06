import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path

class Encrypter:
    def __init__(self, salt: str):
        self.salt = salt

    def generate_key(self, password: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 32,
            salt = self.salt.encode(),
            iterations = 100_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_file(self, file_path: str, input_password: str):
        key = self.generate_key(input_password)
        fernet = Fernet(key)

        read_path = Path(file_path)
        binary_data = read_path.read_bytes()

        encrypted_data = fernet.encrypt(binary_data)

        write_path = Path('encrypted_data.bin')
        write_path.write_bytes(encrypted_data)
        print(f"File encrypted and saved to: {write_path}")

    def decrypt_file(self, path: str, input_password: str):
        key = self.generate_key(input_password)
        fernet = Fernet(key)

        encrypted_data = Path(path).read_bytes()
        decrypted_data = fernet.decrypt(encrypted_data)

        write_path = Path("decrypted_data.rename")
        write_path.write_bytes(decrypted_data)



password = b"insertpasswordhere"
my_salt = "insertsalthere"

encrypter = Encrypter(my_salt)

def display_menu():
    print("E)ncrypt file  D)ecrypt file - Q)uit")
    choice = input("Enter Input:  ")
    return choice

def main():
    while True:
        choice = display_menu()
        if choice == "q":
            break
        if choice == "e":
            print("------------- Encrypt File -------------")
            file_path = input("Path: ")
            file_password = input("Password: ")
            encrypter.encrypt_file(file_path, file_password)
        if choice == "d":
            print("------------- decrypt File -------------")
            file_path = input("Path: ")
            file_password = input("Password: ")
            encrypter.decrypt_file(file_path, file_password)



if __name__ == "__main__":
    main()