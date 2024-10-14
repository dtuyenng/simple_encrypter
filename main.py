import base64
from os.path import expanduser

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path
import json

import customtkinter as ctk
from tkinter import filedialog

from setuptools.monkey import patch_all


def main():
    app = Application()
    app.mainloop()


class Application(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry('600x400')
        self.configure(fg_color="white")

        self.file_selector = FileSelector(self)
        self.password_input = PasswordInput(self, self.file_selector)

class FileSelector(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent,  **kwargs, fg_color = "lightblue")
        self.pack(expand=True, fill="x", padx=10, pady=10)
        self.file_path = ctk.CTkLabel(self, text="Pick a file...",
                                  anchor="w",
                                  font=("Arial", 16),
                                  fg_color="white")
        self.file_path.pack(side="left", padx=10, pady=10, expand=True, fill="x")
        self.button = ctk.CTkButton(self, text="Select File", command=self.pick_file,
                                    width=70)
        self.button.pack(side="right", padx=10)


    def pick_file(self, event=None):
        file_picker = filedialog.askopenfilename()
        if file_picker:
            self.file_path.configure(text=file_picker)

class PasswordInput(ctk.CTkFrame):
    def __init__(self, parent, file_selector, **kwargs):
        super().__init__(parent, **kwargs, fg_color="pink")
        self.pack(expand=True, fill="x", padx=10, pady=10)

        self.file_selector = file_selector.file_path

        self.password_label1 = ctk.CTkEntry(self, placeholder_text="Enter Password", width=200)
        self.password_label1.pack( padx=10, pady=10,)
        self.password_label2 = ctk.CTkEntry(self, placeholder_text="Confirm Password", width=200)
        self.password_label2.pack(padx=10, pady=10, )

        self.encrypt_button = ctk.CTkButton(self, text="Encrypt File", command=self.encrypt,
                                            width=150,
                                            height=50)
        self.encrypt_button.pack()

    def encrypt(self):
        password1 = self.password_label1.get()
        password2 = self.password_label2.get()
        if password1 != password2:
            print("Passwords don't match, try again")
            self.password_label1.delete(0, ctk.END)
            self.password_label2.delete(0, ctk.END)
            self.password_label1.focus()
        else:
            print(self.file_selector.cget("text"))






class Encrypter:
    def __init__(self):
        self.salt = self.import_salt()

    @staticmethod
    def import_salt() -> str:
        json_data = json.loads(Path("config.json").read_text())
        print("Config file loaded.")
        return json_data["salt"]

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

    def decrypt_file(self, file_path: str, input_password: str):
        try:
            key = self.generate_key(input_password)
            fernet = Fernet(key)

            write_path = Path(file_path)
            encrypted_data = write_path.read_bytes()

            decrypted_data = fernet.decrypt(encrypted_data)

            write_path = Path("decrypted_data.rename")
            write_path.write_bytes(decrypted_data)
            print("Decryption Successful: 'decrypted_data.rename' created.")
        except FileNotFoundError:
            print(f"File not found.")
        except InvalidToken:
            print("Decryption failed. The password might be incorrect or the data might be corrupted.")



# def display_menu():
#     print("E)ncrypt file  D)ecrypt file - Q)uit")
#     choice = input("Enter Input:  ")
#     return choice
#
# def main():
#     encrypter = Encrypter()
#     while True:
#         choice = display_menu()
#         if choice == "q":
#             break
#         if choice == "e":
#             print("------------- Encrypt File -------------")
#             file_path = input("Path: ")
#             file_password = input("Password: ")
#             encrypter.encrypt_file(file_path, file_password)
#         if choice == "d":
#             print("------------- decrypt File -------------")
#             file_path = input("Path: ")
#             file_password = input("Password: ")
#             encrypter.decrypt_file(file_path, file_password)



if __name__ == "__main__":
    main()
