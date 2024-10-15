import Encrypter as Encrypter
import customtkinter as ctk
from tkinter import filedialog

def main():
    app = Application()
    app.mainloop()


class Application(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry('600x400')
        self.configure(fg_color="white")

        """ Encrypter """
        self.label1 = ctk.CTkLabel(self, text="Encrypter").pack()
        self.file_selector = TheEncrypter(self)
        self.password_input = PasswordInput(self, self.file_selector)

        """ Decrypter """

class TheEncrypter(ctk.CTkFrame):
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
        super().__init__(parent, **kwargs)
        self.pack(expand=True, fill="x", padx=10, pady=10)

        self.file_selector = file_selector


        self.password_label1 = ctk.CTkEntry(self, placeholder_text="Enter Password", width=200)
        self.password_label1.pack( padx=10, pady=10,)
        self.password_label2 = ctk.CTkEntry(self, placeholder_text="Confirm Password", width=200)
        self.password_label2.pack(padx=10)


        self.encrypt_button = ctk.CTkButton(self, text="Encrypt File", command=self.encrypt,
                                            width=150,
                                            height=50)
        self.encrypt_button.pack()

    def encrypt(self):
        password1 = self.password_label1.get()
        password2 = self.password_label2.get()

        file_path = self.file_selector.file_path.cget("text")
        if password1 != password2:
            print("Passwords don't match, try again")
            self.password_label1.delete(0, ctk.END)
            self.password_label2.delete(0, ctk.END)
            self.password_label1.focus()
        else:
            encrypter = Encrypter()
            print(f"path: {file_path}")
            encrypter.encrypt_file(file_path, password1)



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
