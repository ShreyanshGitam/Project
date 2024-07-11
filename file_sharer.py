import os
import socket
import sqlite3
import random
import shutil
from datetime import datetime
from tkinter import *
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk
from PIL import Image, ImageTk  # Ensure Pillow is installed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import bcrypt

# AES key for encryption
KEY = b'0123456789abcdef'  # 16-byte key for AES-128
STORAGE_DIR = "storage"

# Global variables to store images and 4-digit code
send_image = None
receive_image = None
image_icon1 = None
codes = {}
current_user = None
current_path = None

# Database setup
conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT PRIMARY KEY, password_hash TEXT, created_at TEXT)''')
conn.commit()

# Create storage directory if it doesn't exist
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

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
    user_dir = os.path.join(STORAGE_DIR, f"{username}_dir")
    try:
        c.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)", (username, hashed_password, created_at))
        conn.commit()
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)
        return True
    except sqlite3.IntegrityError:
        return False

def login_window():
    global root, current_user
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
        global current_user
        username = username_entry.get()
        password = password_entry.get()
        if authenticate(username, password):
            current_user = username
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

def generate_code():
    return str(random.randint(1000, 9999))

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
            code = generate_code()
            codes[code] = encrypted_data
            conn.send(code.encode())
            conn.close()
            user_dir = os.path.join(STORAGE_DIR, f"{current_user}_dir")
            with open(os.path.join(user_dir, f"{code}.bin"), 'wb') as f:
                f.write(encrypted_data)
            messagebox.showinfo("Success", f"File has been transmitted successfully! Code: {code}")
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
            code = receive_code.get()
            s = socket.socket()
            port = 8080
            s.connect((iD, port))
            s.send(code.encode())
            user_dir = os.path.join(STORAGE_DIR, f"{current_user}_dir")
            file_path = os.path.join(user_dir, f"{code}.bin")
            if not os.path.exists(file_path):
                raise ValueError("Invalid code or code expired")
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = decrypt(encrypted_data, KEY)
            filename = f"received_{code}.txt"
            with open(os.path.join(user_dir, filename), 'wb') as file:
                file.write(decrypted_data)
            s.close()
            messagebox.showinfo("Success", f"File has been received and saved as {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    main.iconphoto(False, image_icon1)

    Label(main, text="Receive Window", font=('Arial', 20), bg="#1e1e1e", fg="#ffffff").place(x=110, y=0)

    Label(main, text="Input sender id", font=('arial', 10, 'bold'), bg="#1e1e1e", fg="#ffffff").place(x=20, y=50)
    senderID = Entry(main, width=25, fg="black", border=2, bg='white', font=('arial', 15))
    senderID.place(x=20, y=75)
    senderID.focus()

    Label(main, text="Enter 4-digit code:", font=('arial', 10, 'bold'), bg="#1e1e1e", fg="#ffffff").place(
        x=20, y=120)
    receive_code = Entry(main, width=25, fg="black", border=2, bg="white", font=('arial', 15))
    receive_code.place(x=20, y=145)

    rr = Button(main, text="Receive", compound=LEFT, width=13, bg="#39c790", font="arial 14 bold",
                command=receiver)
    rr.place(x=135, y=190)

    main.mainloop()

def file_management_window():
    global current_path
    current_path = os.path.join(STORAGE_DIR, f"{current_user}_dir")

    def load_files(path):
        for widget in file_display_frame.winfo_children():
            widget.destroy()
        files = os.listdir(path)
        row, col = 0, 0
        for file in files:
            if col > 3:
                col = 0
                row += 1
            filepath = os.path.join(path, file)

            # Determine icon based on file extension
            _, ext = os.path.splitext(filepath)
            ext = ext.lower()
            icon_path = "Images/file.png"  # Default icon
            if ext in ['.txt']:
                icon_path = "Images/txt.png"
            elif ext in ['.pdf']:
                icon_path = "Images/pdf.png"
            elif ext in ['.jpg', '.jpeg', '.png']:
                icon_path = "Images/image.png"
            elif ext in ['.doc', '.docx']:
                icon_path = "Images/doc.png"
            elif ext in ['.ppt', '.pptx']:
                icon_path = "Images/ppt_icon.png"
            elif ext in ['.xls', '.xlsx']:
                icon_path = "Images/xls.png"
            elif ext in ['.mp3', '.wav']:
                icon_path = "Images/audio.png"
            elif ext in ['.mp4', '.mkv']:
                icon_path = "Images/video_icon.png"
            elif ext in ['.zip', '.rar']:
                icon_path = "Images/zip.png"

            if os.path.isdir(filepath):
                icon_path = "Images/folder_icon.png"

            icon = Image.open(icon_path)
            icon = icon.resize((64, 64), Image.LANCZOS)
            img = ImageTk.PhotoImage(icon)
            icon_label = Label(file_display_frame, image=img, text=file, compound="top", bg="#1e1e1e", fg="white")
            icon_label.image = img
            icon_label.grid(row=row, column=col, padx=20, pady=20)
            if os.path.isdir(filepath):
                icon_label.bind("<Double-1>", lambda e, p=filepath: view_folder(p))
            col += 1

    def view_folder(path):
        global current_path
        current_path = path
        load_files(current_path)
        back_button.config(state=NORMAL, bg="red")

    def back():
        global current_path
        if current_path != os.path.join(STORAGE_DIR, f"{current_user}_dir"):
            current_path = os.path.dirname(current_path)
            load_files(current_path)
            if current_path == os.path.join(STORAGE_DIR, f"{current_user}_dir"):
                back_button.config(state=DISABLED, bg="gray")

    def delete_file():
        selected_file = file_display_frame.focus_get().cget("text")
        if selected_file:
            os.remove(os.path.join(current_path, selected_file))
            load_files(current_path)
            messagebox.showinfo("Success", f"File {selected_file} has been deleted")

    def rename_file():
        selected_file = file_display_frame.focus_get().cget("text")
        if selected_file:
            new_name = simpledialog.askstring("Rename File", "Enter new name for the file:", initialvalue=selected_file)
            if new_name:
                os.rename(os.path.join(current_path, selected_file), os.path.join(current_path, new_name))
                load_files(current_path)
                messagebox.showinfo("Success", f"File has been renamed to {new_name}")

    def create_folder():
        new_folder_name = simpledialog.askstring("Create Folder", "Enter name for the new folder:")
        if new_folder_name:
            os.makedirs(os.path.join(current_path, new_folder_name))
            load_files(current_path)
            messagebox.showinfo("Success", f"Folder {new_folder_name} has been created")

    def upload_file():
        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title='Select File to Upload')
        if filename:
            try:
                destination = os.path.join(current_path, os.path.basename(filename))
                with open(filename, 'rb') as fsrc, open(destination, 'wb') as fdst:
                    fdst.write(fsrc.read())
                load_files(current_path)
                messagebox.showinfo("Success", "File has been uploaded successfully")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")

    def download_file():
        selected_file = file_display_frame.focus_get().cget("text")
        if selected_file:
            save_path = filedialog.asksaveasfilename(initialdir=os.getcwd(), title='Save File As', initialfile=selected_file)
            if save_path:
                try:
                    with open(os.path.join(current_path, selected_file), 'rb') as fsrc, open(save_path, 'wb') as fdst:
                        fdst.write(fsrc.read())
                    messagebox.showinfo("Success", "File has been downloaded successfully")
                except Exception as e:
                    messagebox.showerror("Error", f"An error occurred: {e}")

    def move_file():
        selected_file = file_display_frame.focus_get().cget("text")
        if selected_file:
            new_path = filedialog.askdirectory(initialdir=current_path, title='Select Destination Folder')
            if new_path:
                try:
                    shutil.move(os.path.join(current_path, selected_file), os.path.join(new_path, selected_file))
                    load_files(current_path)
                    messagebox.showinfo("Success", f"File has been moved to {new_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"An error occurred: {e}")

    window = Toplevel(root)
    window.title("File Management")
    window.geometry('800x600')
    center_window(window, 830, 600)
    window.configure(bg="#1e1e1e")
    window.resizable(True, True)

    Label(window, text="File Management", font=('Arial', 20), bg="#1e1e1e", fg="#ffffff").pack(pady=10)

    file_display_frame = Frame(window, bg="#1e1e1e")
    file_display_frame.pack(fill=BOTH, expand=YES)

    button_frame = Frame(window, bg="#1e1e1e")
    button_frame.pack(pady=10)

    Button(button_frame, text="Refresh", width=10, height=1, bg="blue", fg="white", command=lambda: load_files(current_path)).grid(row=0, column=0, padx=10)
    Button(button_frame, text="Delete", width=10, height=1, bg="red", fg="white", command=delete_file).grid(row=0, column=1, padx=10)
    Button(button_frame, text="Rename", width=10, height=1, bg="yellow", fg="black", command=rename_file).grid(row=0, column=2, padx=10)
    Button(button_frame, text="Create Folder", width=12, height=1, bg="cyan", fg="black", command=create_folder).grid(row=0, column=3, padx=10)
    Button(button_frame, text="Upload", width=10, height=1, bg="purple", fg="white", command=upload_file).grid(row=0, column=4, padx=10)
    Button(button_frame, text="Download", width=12, height=1, bg="orange", fg="black", command=download_file).grid(row=0, column=5, padx=10)
    Button(button_frame, text="Move", width=10, height=1, bg="brown", fg="white", command=move_file).grid(row=0, column=6, padx=10)
    back_button = Button(button_frame, text="Back", width=10, height=1, bg="gray", fg="white", command=back, state=DISABLED)
    back_button.grid(row=0, column=7, padx=10)

    load_files(current_path)

    window.mainloop()

# Start the application
login_window()
