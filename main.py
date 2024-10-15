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
        # self.password_input = PasswordInput(self, self.file_selector)

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

        self.select_button = ctk.CTkButton(self, text="Select File", command=self.pick_file,
                                    width=70)
        self.select_button.pack(side="right", padx=10)

        self.password_input_frame(parent, self.file_path)


    def pick_file(self, event=None):
        file_picker = filedialog.askopenfilename()
        if file_picker:
            self.file_path.configure(text=file_picker)

    def password_input_frame(self, parent, file_path):

        password_frame = ctk.CTkFrame(parent)
        password_frame.pack(expand=True, fill="x", padx=10, pady=10)

        password_label1 = ctk.CTkEntry(self, placeholder_text="Enter Password", width=200)
        password_label1.pack(padx=10, pady=10, )
        password_label2 = ctk.CTkEntry(self, placeholder_text="Confirm Password", width=200)
        password_label2.pack(padx=10)

        encrypt_button = ctk.CTkButton(self, text="Encrypt File",
                                        command= lambda: self.encrypt(file_path, password_label1, password_label2),
                                        width=150,
                                        height=50)
        encrypt_button.pack()

    def encrypt(self, file_path, password1_entry, password2_entry):
        password1 = password1_entry.get()
        password2 = password2_entry.get()

        file_path = file_path.cget("text")
        if password1 != password2:
            print("Passwords don't match, try again")
            # Clear both password fields
            password1_entry.delete(0, ctk.END)
            password2_entry.delete(0, ctk.END)
            password1_entry.focus()
        else:
            encrypter = Encrypter.Encrypter()
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
