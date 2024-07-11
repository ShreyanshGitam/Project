import os
import socket
import sqlite3
from datetime import datetime
from tkinter import *
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import bcrypt

# AES key for encryption
KEY = b'0123456789abcdef'  # 16-byte key for AES-128

# Global variables to store images
send_image = None
receive_image = None
image_icon1 = None

# Database setup
conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT PRIMARY KEY, password_hash TEXT, created_at TEXT)''')
conn.commit()

def load_images():
    global send_image, receive_image, image_icon1, imageicon
    send_image = PhotoImage(file="Images/send.png").subsample(8, 8)  # Adjust size
    receive_image = PhotoImage(file="Images/received.png").subsample(8, 8)  # Adjust size
    image_icon1 = PhotoImage(file="Images/send.png").subsample(4, 4)  # Adjust size

def center_window(window, width, height):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    window.geometry(f'{width}x{height}+{x}+{y}')

def encrypt(data, key):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def authenticate(username, password):
    c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    result = c.fetchone()
    if result and check_password(password, result[0]):
        return True
    return False

def register(username, password):
    hashed_password = hash_password(password)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        c.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)", (username, hashed_password, created_at))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def login_window():
    global root
    root = Tk()
    root.title("Login")
    root.geometry("300x200")
    center_window(root, 300, 200)
    root.configure(bg="#1e1e1e")
    root.resizable(False, False)

    Label(root, text="Username:", bg="#1e1e1e", fg="#ffffff").place(x=50, y=50)
    username_entry = Entry(root, width=25, fg="black", border=2, bg='white')
    username_entry.place(x=130, y=50)
    username_entry.focus()

    Label(root, text="Password:", bg="#1e1e1e", fg="#ffffff").place(x=50, y=100)
    password_entry = Entry(root, width=25, fg="black", border=2, bg='white', show='*')
    password_entry.place(x=130, y=100)

    def login():
        username = username_entry.get()
        password = password_entry.get()
        if authenticate(username, password):
            root.destroy()
            main_window()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def open_register():
        register_window()

    Button(root, text="Login", width=10, height=1, bg="blue", fg="white", command=login).place(x=130, y=150)
    Button(root, text="Register", width=10, height=1, bg="green", fg="white", command=open_register).place(x=50, y=150)

    root.mainloop()

def register_window():
    window = Toplevel(root)
    window.title("Register")
    window.geometry("300x250")
    center_window(window, 300, 250)
    window.configure(bg="#1e1e1e")
    window.resizable(False, False)

    Label(window, text="Username:", bg="#1e1e1e", fg="#ffffff").place(x=50, y=50)
    username_entry = Entry(window, width=25, fg="black", border=2, bg='white')
    username_entry.place(x=130, y=50)
    username_entry.focus()

    Label(window, text="Password:", bg="#1e1e1e", fg="#ffffff").place(x=50, y=100)
    password_entry = Entry(window, width=25, fg="black", border=2, bg='white', show='*')
    password_entry.place(x=130, y=100)

    def register_user():
        username = username_entry.get()
        password = password_entry.get()
        if register(username, password):
            messagebox.showinfo("Success", "Registration successful")
            window.destroy()
        else:
            messagebox.showerror("Error", "Username already exists")

    Button(window, text="Register", width=10, height=1, bg="green", fg="white", command=register_user).place(x=130, y=150)

    window.mainloop()

def main_window():
    global root
    root = Tk()
    root.title("Share Files")
    root.geometry("600x400")
    center_window(root, 600, 400)
    root.configure(bg="#1e1e1e")
    root.resizable(False, False)

    load_images()

    # Creating a frame to hold the content
    main_frame = Frame(root, bg="#1e1e1e")
    main_frame.pack(fill=BOTH, expand=YES)

    # Adding title
    app_name = Label(main_frame, text="File Sharer", font=('Broadway', 20, 'bold'), bg="#1e1e1e", fg="#ffffff")
    app_name.pack(pady=20)

    # Create buttons
    button_frame = Frame(main_frame, bg="#1e1e1e")
    button_frame.pack(pady=20)

    send_button = Button(button_frame, image=send_image, bg="#1e1e1e", bd=0, command=Send, highlightthickness=0,
                         activebackground="#1e1e1e")
    send_button.grid(row=0, column=0, padx=20)

    receive_button = Button(button_frame, image=receive_image, bg="#1e1e1e", bd=0, command=Receive,
                            highlightthickness=0, activebackground="#1e1e1e")
    receive_button.grid(row=0, column=1, padx=20)

    # Label Section
    send_label = Label(button_frame, text="Send", font=('Verdana', 15, 'bold'), bg="#1e1e1e", fg="#ffffff")
    send_label.grid(row=1, column=0, pady=10)

    receive_label = Label(button_frame, text="Receive", font=('Verdana', 15, 'bold'), bg="#1e1e1e", fg="#ffffff")
    receive_label.grid(row=1, column=1, pady=10)

    file_mgmt_button = Button(main_frame, text="File Management", width=20, height=2, bg="#39c790", font="arial 14 bold",
                              command=file_management_window)
    file_mgmt_button.pack(pady=20)

    root.mainloop()

def Send():
    window = Toplevel(root)
    window.title("Send")
    window.geometry('400x300')
    center_window(window, 400, 300)
    window.configure(bg="#1e1e1e")
    window.resizable(False, False)

    def select_file():
        global filename
        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title='Select File')
        if filename:
            file_label.config(text=filename)

    def sender():
        try:
            s = socket.socket()
            host = socket.gethostname()
            port = 8080
            s.bind((host, port))
            s.listen(1)
            conn, addr = s.accept()
            with open(filename, 'rb') as file:
                file_data = file.read()
            encrypted_data = encrypt(file_data, KEY)
            conn.send(encrypted_data)
            conn.close()
            messagebox.showinfo("Success", "File has been transmitted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    window.iconphoto(False, image_icon1)
    host = socket.gethostname()
    Label(window, text=f'Your Device ID: {host}', font='Verdana 12 bold', bg='#1e1e1e', fg='white').place(x=10, y=10)
    file_label = Label(window, text="No file selected", bg='#1e1e1e', fg='white')
    file_label.place(x=10, y=50)
    Button(window, text="Select File", width=12, height=1, font='arial 12 bold', bg="yellow", fg="blue",
           command=select_file).place(x=10, y=80)
    Button(window, text="SEND", width=8, height=1, font='arial 12 bold', bg='#000', fg="#fff", command=sender).place(
        x=300, y=80)

    window.mainloop()

def Receive():
    main = Toplevel(root)
    main.title("Receive")
    main.geometry('400x300')
    center_window(main, 400, 300)
    main.configure(bg="#1e1e1e")
    main.resizable(False, False)

    def receiver():
        try:
            iD = senderID.get()
            filename1 = incoming_file.get()
            s = socket.socket()
            port = 8080
            s.connect((iD, port))
            encrypted_data = s.recv(4096)  # Increased buffer size
            decrypted_data = decrypt(encrypted_data, KEY)
            with open(filename1, 'wb') as file:
                file.write(decrypted_data)
            s.close()
            messagebox.showinfo("Success", "File has been received successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    main.iconphoto(False, image_icon1)

    Label(main, text="Receive Window", font=('Arial', 20), bg="#1e1e1e", fg="#ffffff").place(x=110, y=0)

    Label(main, text="Input sender id", font=('arial', 10, 'bold'), bg="#1e1e1e", fg="#ffffff").place(x=20, y=50)
    senderID = Entry(main, width=25, fg="black", border=2, bg='white', font=('arial', 15))
    senderID.place(x=20, y=75)
    senderID.focus()

    Label(main, text="filename for the incoming file:", font=('arial', 10, 'bold'), bg="#1e1e1e", fg="#ffffff").place(
        x=20, y=120)
    incoming_file = Entry(main, width=25, fg="black", border=2, bg="white", font=('arial', 15))
    incoming_file.place(x=20, y=145)

    rr = Button(main, text="Receive", compound=LEFT, width=13, bg="#39c790", font="arial 14 bold",
                command=receiver)
    rr.place(x=135, y=190)

    main.mainloop()

def file_management_window():
    window = Toplevel(root)
    window.title("File Management")
    window.geometry('600x400')
    center_window(window, 600, 400)
    window.configure(bg="#1e1e1e")
    window.resizable(False, False)

    Label(window, text="File Management", font=('Arial', 20), bg="#1e1e1e", fg="#ffffff").pack(pady=10)

    # Listbox to display files
    file_listbox = Listbox(window, width=80, height=15, bg='#1e1e1e', fg='white')
    file_listbox.pack(pady=10)

    # Load files from the directory
    def load_files():
        file_listbox.delete(0, END)
        files = os.listdir(".")
        for file in files:
            if os.path.isfile(file):
                file_listbox.insert(END, file)

    load_files()

    def delete_file():
        selected_file = file_listbox.get(ACTIVE)
        if selected_file:
            os.remove(selected_file)
            load_files()
            messagebox.showinfo("Success", f"File {selected_file} has been deleted")

    def view_file():
        selected_file = file_listbox.get(ACTIVE)
        if selected_file:
            os.startfile(selected_file)

    Button(window, text="Refresh", width=10, height=1, bg="blue", fg="white", command=load_files).pack(side=LEFT, padx=10, pady=10)
    Button(window, text="View", width=10, height=1, bg="green", fg="white", command=view_file).pack(side=LEFT, padx=10, pady=10)
    Button(window, text="Delete", width=10, height=1, bg="red", fg="white", command=delete_file).pack(side=LEFT, padx=10, pady=10)

    window.mainloop()

# Start the application
login_window()
