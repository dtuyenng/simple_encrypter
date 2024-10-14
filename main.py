import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path
import json

import customtkinter as ctk
from tkinter import filedialog

def main():
    app = Application()
    # frame = Frame(app)
    file_selector = FileSelector(app)
    file_selector.pack()
    app.mainloop()


class Application(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.geometry('600x400')

class Frame(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.pack()
        label = ctk.CTkLabel(self, text="Hello World")
        label.pack()
        entry = ctk.CTkEntry(self)
        entry.pack()

        # button = CustomButton(self, text="Press Me", command=self.button_press)


    # def pick_file_event(self, event=None):
    #     file_picker = filedialog.askopenfilename()
    #     if file_picker:
    #         # Update the label text
    #         self.pick_file_label.configure(text=f"{file_picker}")

    @staticmethod
    def button_press(event=None):
        print("Button Pressed")

class FileSelector(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.label = ctk.CTkLabel(self, text="Pick a file...", font=("Arial", 16))
        self.label.pack()
        self.button = ctk.CTkButton(self, text="Select File", command=self.pick_file)
        self.button.pack()

    def pick_file(self, event=None):
        file_picker = filedialog.askopenfilename()
        if file_picker:
            self.label.configure(text=file_picker)




class CustomButton(ctk.CTkButton):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.pack()





# button = ctk.CTkButton(app, text="Press Me",
#                        fg_color= "red",
#                        corner_radius= 20,
#                        command = lambda: print("Hello World"))
# button.pack()

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
