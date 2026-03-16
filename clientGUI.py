from tkinter import *
from tkinter import ttk, filedialog
from tkinter import messagebox
from client import Client
from src.utils.createLogger import createLogger
import logging
from pathlib import Path


logger = createLogger("GUI")
logger.setLevel(logging.DEBUG)
mainwnd = None


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
            logger.info("Failed log in")
        else:
            messagebox.showinfo("Successfully",
                                f'''Log in success\n
                                Info: {result_body["message"]}\n
                                Server code: {code}''')
            self.root.destroy()
            mainwnd = MainWindow(self.client, login)


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
            logger.info("Failed registration")
            
        else:
            messagebox.showinfo("Successfully",
                                f'''Registration success\n
                                Info: {result_body["message"]}\n
                                Server code: {code}''')
            logger.info("Success registration")
            self.root.destroy()
            mainwnd = MainWindow(self.client, login)


class MainWindow:
    def __init__(self, client: Client, login):
        self.client = client
        self.login = login
        self.root = None
        self.build_window()

    def build_window(self):
        self.root = Tk()
        self.root.title(f"File Manager — {self.login}")
        self.root.configure(bg="#3E3D3D")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#262626")
        style.configure("Title.TLabel",
                        background="#262626",
                        font=("Segoe UI", 26, "bold"),
                        foreground="#ffffff")

        style.configure("Action.TButton",
                        background="#0d6efd",
                        foreground="white",
                        font=("Segoe UI", 14, "bold"),
                        padding=(24, 14),
                        borderwidth=0)
        style.map("Action.TButton",
                  background=[("active", "#0a58ca")],
                  foreground=[("active", "white")])

        style.configure("Danger.TButton",
                        background="#dc3545",
                        foreground="white",
                        font=("Segoe UI", 14, "bold"),
                        padding=(24, 14),
                        borderwidth=0)
        style.map("Danger.TButton",
                  background=[("active", "#bb2d3b")],
                  foreground=[("active", "white")])

        width = 1000
        height = 562
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.root.resizable(False, False)

        main_frame = ttk.Frame(self.root, padding=40, style="TFrame")
        main_frame.pack(expand=True, fill=BOTH)

        title_label = ttk.Label(main_frame, text=f"Welcome, {self.login}!", style="Title.TLabel")
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 30), sticky="ew")

        pst_btn = ttk.Button(main_frame, text="Load", style="Action.TButton", command=self.on_pst)
        pst_btn.grid(row=1, column=0, sticky="ew", padx=(0, 20), pady=(0, 10))

        get_btn = ttk.Button(main_frame, text="Download", style="Action.TButton", command=self.on_get)
        get_btn.grid(row=2, column=0, sticky="ew", padx=(0, 20), pady=(0, 10))

        lis_btn = ttk.Button(main_frame, text="List", style="Action.TButton", command=self.on_list)
        lis_btn.grid(row=3, column=0, sticky="ew", padx=(0, 20), pady=(0, 10))

        del_btn = ttk.Button(main_frame, text="Delete", style="Danger.TButton", command=self.on_del)
        del_btn.grid(row=4, column=0, sticky="ew", padx=(0, 20), pady=(0, 10))

        self.file_list = Listbox(main_frame,
                            bg="#1f1f1f",
                            fg="#e0e0e0",
                            font=("Segoe UI", 14),
                            selectbackground="#fd5050",
                            selectforeground="#ffffff",
                            activestyle="none",
                            relief="flat",
                            bd=2,
                            highlightthickness=0,
                            width=70,
                            height=18)
        self.file_list.grid(row=1, column=1, rowspan=4, columnspan=2, sticky="nsew", padx=(20, 0))

        main_frame.grid_columnconfigure(0, weight=0)
        main_frame.grid_columnconfigure(1, weight=1)
        main_frame.grid_columnconfigure(2, weight=1)

        main_frame.grid_rowconfigure(0, weight=0)  
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_rowconfigure(2, weight=1)
        main_frame.grid_rowconfigure(3, weight=1)
        main_frame.grid_rowconfigure(4, weight=1)

        self.root.mainloop()


    def on_pst(self):
        print("on post")

        file_path = None
        file_path = filedialog.askopenfilename(
            title="Choose file",
            filetypes=[("Text files", "*.txt"),
                       ("All files", "*.*")]
        )

        logger.debug(f"File: {file_path}")
        if file_path == '': return

        file_path = Path(file_path)
        code, body = self.client.sendData(file_path)

        logger.info(f"Code: {code}")
        logger.info(f"Body: {body}")

        self.on_list()


    def on_get(self):
        print("on get")

        select = self.file_list.curselection()

        if not select:
            messagebox.showerror(title="Download error",
                                 message='''Update file names list and select file to download.''')
            return
        
        self.file_list.select_clear(0, END)
        
        index = select[0]
        text = self.file_list.get(index)
        logger.debug(f"Choosen: {text} (index {index})")

        file_name = text[:80].strip()
        logger.debug(f"File name: {file_name}")

        directory_path = None
        directory_path = filedialog.askdirectory(
            title="Choose foder"
        )

        logger.debug(f"Directory: {directory_path}")
        if directory_path == '': return

        directory_path = Path(directory_path + "/" + file_name)

        code, body = self.client.getFile(directory_path)
        logger.info(f"Code recived: {code}")
        logger.info(f"Body recived: {body}")

        self.on_list()


    def on_list(self):
        print("on list")


        code, body, names = self.client.listData()
        logger.info(f"Code recived: {code}")
        logger.info(f"Body recived: {body}")
        logger.info(f"Names recived: {names}")

        self.file_list.delete(0, END)

        if names == []:
            logger.debug("Empty -> quit") 
            self.file_list.insert(END, "Empty")
            return

        for name, size_raw in names:
            size_str = self.__format_bytes(int(size_raw))
            logger.debug(f"Name: {name}")
            logger.debug(f"Size: {size_str}")
            self.file_list.insert(END, f"{name:<{80}}{size_str:>{20}}")
            
        logger.debug("names listed")


    def on_del(self):
        select = self.file_list.curselection()

        if not select:
            messagebox.showerror(title="Delete error",
                                 message='''Update file names list and select file to delete.''')
            return
        
        self.file_list.select_clear(0, END)
        
        index = select[0]
        text = self.file_list.get(index)
        logger.debug(f"Choosen: {text} (index {index})")

        file_name = text[:80].strip()
        logger.debug(f"File name: {file_name}")


        code, body = self.client.delFile(file_name)
        logger.info(f"Code recived: {code}")
        logger.info(f"Body recived: {body}")

        self.on_list()


    def __format_bytes(self, size: int):
        if size < 1024:
            return f"{size} B"
        elif size < 1024 ** 2:
            return f"{size / 1024:.1f} KB"
        elif size < 1024 ** 3:
            return f"{size / (1024 ** 2):.1f} MB"
        else:
            return f"{size / (1024 ** 3):.1f} GB"


if __name__ == "__main__":
    wins = AUTREGWindow()