from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from client import Client
from src.utils.createLogger import createLogger
import logging


logger = createLogger("GUI")
logger.setLevel(logging.DEBUG)


class AUTREGWindow:
    def __init__(self):
        self.root = None
        self.client = Client(host="localhost",port=9090)
        result = self.client.connect()
        if not result:
            messagebox.showerror("Error", "Connection to server failed")
            return
        self.build_window()

    def build_window(self):
        self.root = Tk()
        self.root.title("Login / Registration")
        self.root.configure(bg="#3E3D3D")   

        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TFrame", background="#262626")
        style.configure("TLabel",
                        background="#262626",
                        foreground="#e0e0e0",
                        font=("Segoe UI", 14))
        style.configure("Title.TLabel",
                        background="#262626",
                        font=("Segoe UI", 26, "bold"),
                        foreground="#ffffff")

        style.configure("TEntry",
                        font=("Segoe UI", 20),
                        padding=10,
                        fieldbackground="#1f1f1f",
                        foreground="#ffffff",
                        insertcolor="#ffffff",
                        borderwidth=2,
                        relief="flat")
        style.map("TEntry",
                  fieldbackground=[("focus", "#2a2a2a")],
                  bordercolor=[("focus", "#fd5050")])

        style.configure("Login.TButton",
                        background="#0d6efd",
                        foreground="white",
                        font=("Segoe UI", 14, "bold"),
                        padding=(24, 14),
                        borderwidth=0)
        style.map("Login.TButton",
                  background=[("active", "#0a58ca")],
                  foreground=[("active", "white")])

        style.configure("Register.TButton",
                        background="#00c853",
                        foreground="white",
                        font=("Segoe UI", 14, "bold"),
                        padding=(24, 14),
                        borderwidth=0)
        style.map("Register.TButton",
                  background=[("active", "#00963d")],
                  foreground=[("active", "white")])

        width = 420
        height = 400
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2 - 40
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.root.resizable(False, False)

        main_frame = ttk.Frame(self.root, padding=40, style="TFrame")
        main_frame.pack(expand=True, fill=BOTH)

        title_label = ttk.Label(main_frame, text="Welcome!", style="Title.TLabel")
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 30), sticky="ew")

        login_label = ttk.Label(main_frame, text="Login")
        login_label.grid(row=1, column=0, sticky="w", pady=(0, 5))
        
        self.login_entry = ttk.Entry(main_frame, width=30, style="TEntry", font=("Segoe UI", 12), )
        self.login_entry.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 15))
        self.login_entry.focus()

        password_label = ttk.Label(main_frame, text="Password")
        password_label.grid(row=3, column=0, sticky="w", pady=(0, 5))
        
        self.password_entry = ttk.Entry(main_frame, width=30, show="●")
        self.password_entry.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 25))

        login_btn = ttk.Button(main_frame, 
                               text="Log In", 
                               style="Login.TButton",
                               command=self.on_login)
        login_btn.grid(row=5, column=0, sticky="ew", padx=(0, 10))

        register_btn = ttk.Button(main_frame, 
                                  text="Sign Up", 
                                  style="Register.TButton",
                                  command=self.on_register)
        register_btn.grid(row=5, column=1, sticky="ew")

        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)

        self.root.mainloop()

    def on_login(self):
        login = self.login_entry.get()
        logger.debug(f"Login : {login}")
        password = self.password_entry.get()
        logger.debug(f"password: {password}")
        code, result_body = None, None
        try:
            code, result_body = self.client.AUTorREG("AUT", login, password)
        except Exception as ex:
            logger.exception("Error during login : ")

        if  not result_body["success"] : 
            messagebox.showerror("Log in error", 
                                 f'''Log in failed\n
                                 Error: {result_body["message"]}\n
                                 Server code: {code}''')
        else:
            messagebox.showinfo("Successfully",
                                f'''Log in success\n
                                Info: {result_body["message"]}\n
                                Server code: {code}''')
            self.root.destroy()



    def on_register(self):
        login = self.login_entry.get()
        logger.debug(f"Login : {login}")
        password = self.password_entry.get()
        logger.debug(f"password: {password}")
        code, result_body = None, None
        try:
            code, result_body = self.client.AUTorREG("REG", login, password)
        except Exception as ex:
            logger.exception("Error during registration : ")

        if  not result_body["success"] : 
            messagebox.showerror("Registration error", 
                                 f'''Registration failed\n
                                 Error: {result_body["message"]}\n
                                 Server code: {code}''')
        else:
            messagebox.showinfo("Successfully",
                                f'''Registration success\n
                                Info: {result_body["message"]}\n
                                Server code: {code}''')
            self.root.destroy()


if __name__ == "__main__":
    app = AUTREGWindow()