import os
import socket
import sqlite3
import random
import shutil
import threading
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

# Global variables to store images
codes = {}
current_user = None
current_path = None
selected_files = set()
move_mode = False

# Sqlite3 Database setup
conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT PRIMARY KEY, password_hash TEXT, created_at TEXT)''')
conn.commit()

# Create storage directory if it doesn't exist
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)


def load_images():
    global image_cache
    image_cache = {}

    def load_image(image_path):
        icon = Image.open(image_path)
        icon = icon.resize((64, 64), Image.LANCZOS)
        return ImageTk.PhotoImage(icon)

    image_cache['file'] = load_image("Images/file.png")
    image_cache['txt'] = load_image("Images/txt.png")
    image_cache['pdf'] = load_image("Images/pdf.png")
    image_cache['image'] = load_image("Images/image.png")
    image_cache['doc'] = load_image("Images/doc.png")
    image_cache['ppt'] = load_image("Images/ppt.png")
    image_cache['xls'] = load_image("Images/xls.png")
    image_cache['audio'] = load_image("Images/audio.png")
    image_cache['video'] = load_image("Images/video.png")
    image_cache['zip'] = load_image("Images/zip.png")
    image_cache['folder'] = load_image("Images/folder.png")


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
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
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
    center_window(root, 280, 140)
    root.configure(bg="#1e1e1e")
    root.resizable(False, False)

    Label(root, text="Username:", bg="#1e1e1e", fg="#ffffff").place(x=20, y=20)
    username_entry = Entry(root, width=25, fg="black", border=2, bg='white')
    username_entry.place(x=90, y=20)
    username_entry.focus()

    Label(root, text="Password:", bg="#1e1e1e", fg="#ffffff").place(x=20, y=50)
    password_entry = Entry(root, width=25, fg="black", border=2, bg='white', show='*')
    password_entry.place(x=90, y=50)

    def login():
        global current_user
        username = username_entry.get()
        password = password_entry.get()
        if authenticate(username, password):
            current_user = username
            root.destroy()
            file_management_window()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def open_register():
        register_window()

    Button(root, text="Login", width=10, height=1, bg="blue", fg="white", command=login).place(x=160, y=90)
    Button(root, text="Register", width=10, height=1, bg="green", fg="white", command=open_register).place(x=50, y=90)

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


def generate_code():
    return str(random.randint(1000, 9999))


def generate_aes_key():
    return os.urandom(16)


def send_files(new_key, key_label, selected_files):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        host = socket.gethostname()
        port = 8080
        s.bind((host, port))
        s.listen(1)
        conn, addr = s.accept()

        for selected_file_path in selected_files:
            with open(selected_file_path, 'rb') as file:
                file_data = file.read()
            decrypted_data = decrypt(file_data, KEY)
            re_encrypted_data = encrypt(decrypted_data, new_key)

            # Send the file name and size first
            file_name = os.path.basename(selected_file_path)
            file_size = len(re_encrypted_data)
            conn.sendall(f"{file_name}\n{file_size}\n".encode())
            # Then send the file data
            conn.sendall(re_encrypted_data)

        conn.close()
        s.close()
        key_label.config(text=f"New AES Key: {new_key.hex()}")
        messagebox.showinfo("Success", "Files have been transmitted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def send_window():
    if selected_files:
        window = Toplevel(root)
        window.title("Send")
        window.geometry('400x300')
        center_window(window, 400, 300)
        window.configure(bg="#1e1e1e")
        window.resizable(False, False)

        new_key = generate_aes_key()
        key_label_text = f"New AES Key: {new_key.hex()}"

        def start_sending():
            threading.Thread(target=send_files, args=(new_key, key_label, list(selected_files))).start()

        def copy_to_clipboard():
            root.clipboard_clear()
            root.clipboard_append(new_key.hex())
            root.update()  # Keeps the clipboard contents after the window is closed
            messagebox.showinfo("Copied", "AES Key copied to clipboard")

        host = socket.gethostname()
        Label(window, text=f'Your Device ID: {host}', font='Verdana 12 bold', bg='#1e1e1e', fg='white').place(x=10, y=10)
        file_label = Label(window, text="Selected files: " + (", ".join([os.path.basename(f) for f in selected_files]) if selected_files else "No files selected"), bg='#1e1e1e', fg='white')
        file_label.place(x=10, y=50)
        Button(window, text="SEND", width=12, height=1, font='arial 12 bold', bg='#000', fg="#fff", command=start_sending).place(x=10, y=80)
        key_label = Label(window, text=key_label_text, bg='#1e1e1e', fg='white')
        key_label.place(x=10, y=120)
        Button(window, text="Copy Key", width=12, height=1, font='arial 12 bold', bg='#007ACC', fg='#fff', command=copy_to_clipboard).place(x=10, y=160)
        window.mainloop()



def receive_files(sender_id):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = 8080
        s.connect((sender_id, port))

        user_dir = os.path.join(STORAGE_DIR, f"{current_user}_dir", "received_files")
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)

        while True:
            # Receive the file name and size first
            header = s.recv(1024).split(b'\n')
            if len(header) < 2:
                break
            file_name = header[0].decode()
            file_size = int(header[1].decode())
            all_data = b""
            while len(all_data) < file_size:
                data = s.recv(1024)
                if not data:
                    break
                all_data += data

            if not all_data:
                break

            filepath = os.path.join(user_dir, file_name)
            with open(filepath, 'wb') as file:
                file.write(all_data)
            messagebox.showinfo("Success", f"File has been received and saved as {file_name}")
            ask_for_key(filepath)

        s.close()
    except socket.gaierror:
        messagebox.showerror("Error", "Hostname could not be resolved. Please check the sender's Device ID.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def receive_window():
    window = Toplevel(root)
    window.title("Receive")
    window.geometry('400x300')
    center_window(window, 400, 300)
    window.configure(bg="#1e1e1e")
    window.resizable(False, False)

    def start_receiving():
        sender_id = senderID.get()
        threading.Thread(target=receive_files, args=(sender_id,)).start()

    Label(window, text="Receive Window", font=('Arial', 20), bg="#1e1e1e", fg="#ffffff").place(x=110, y=0)
    Label(window, text="Input sender ID", font=('arial', 10, 'bold'), bg="#1e1e1e", fg="#ffffff").place(x=20, y=50)
    senderID = Entry(window, width=25, fg="black", border=2, bg='white', font=('arial', 15))
    senderID.place(x=20, y=75)
    senderID.focus()

    rr = Button(window, text="Receive", compound=LEFT, width=13, bg="#39c790", font="arial 14 bold", command=start_receiving)
    rr.place(x=135, y=190)

    window.mainloop()

def ask_for_key(filepath):
    def decrypt_file():
        aes_key = key_entry.get()
        if aes_key:
            try:
                with open(filepath, 'rb') as file:
                    encrypted_data = file.read()
                decrypted_data = decrypt(encrypted_data, bytes.fromhex(aes_key))
                with open(filepath, 'wb') as file:
                    file.write(decrypted_data)
                messagebox.showinfo("Success", "File has been decrypted successfully!")
                key_window.destroy()
            except ValueError as e:
                messagebox.showerror("Error", "Decryption failed. Invalid key or data corruption.")
        else:
            messagebox.showwarning("Warning", "AES key is required to decrypt the file.")

    key_window = Toplevel(root)
    key_window.title("Enter AES Key")
    key_window.geometry('300x150')
    center_window(key_window, 300, 150)
    key_window.configure(bg="#1e1e1e")
    key_window.resizable(False, False)

    Label(key_window, text="Enter AES Key:", font=('Arial', 12), bg="#1e1e1e", fg="#ffffff").place(x=20, y=20)
    key_entry = Entry(key_window, width=25, fg="black", border=2, bg='white', font=('Arial', 12))
    key_entry.place(x=20, y=50)
    key_entry.focus()

    Button(key_window, text="Decrypt", width=10, height=1, bg="green", fg="white", command=decrypt_file).place(x=100, y=90)
    key_window.mainloop()



def file_management_window():
    global root, current_path, selected_files, move_mode
    root = Tk()
    root.title("File Management")
    root.geometry('1100x600')
    center_window(root, 1100, 600)
    root.configure(bg="#1e1e1e")
    root.resizable(True, True)

    Label(root, text="File Management", font=('Arial', 20), bg="#1e1e1e", fg="#ffffff").pack(pady=10)

    current_path = os.path.join(STORAGE_DIR, f"{current_user}_dir")
    selected_files = set()
    move_mode = False

    load_images()

    def custom_rename_dialog(initial_value):
        dialog = Toplevel(root)
        dialog.title("Rename File")
        dialog.geometry("400x200")  # Set the desired size
        center_window(dialog, 350, 135)
        dialog.configure(bg="#1e1e1e")
        dialog.resizable(False, False)

        Label(dialog, text="Enter the New Name:", bg="#1e1e1e", fg="#ffffff").pack(pady=10)
        new_name_var = StringVar(dialog, value=initial_value)
        new_name_entry = Entry(dialog, textvariable=new_name_var, width=40)
        new_name_entry.pack(pady=10)
        new_name_entry.focus()

        def on_submit():
            dialog.new_name = new_name_var.get()
            dialog.destroy()

        Button(dialog, text="Rename", command=on_submit, bg="green", fg="white").pack(pady=10)

        dialog.transient(root)  # Ensure the dialog stays on top of the root window
        dialog.grab_set()  # Ensure all input is directed to this dialog
        root.wait_window(dialog)  # Wait until the dialog is closed

        return getattr(dialog, 'new_name', None)

    def rename_file():
        if selected_files and len(selected_files) == 1:
            selected_file_path = list(selected_files)[0]
            new_name = custom_rename_dialog(initial_value=os.path.basename(selected_file_path))
            if new_name:
                new_path = os.path.join(current_path, new_name)
                os.rename(selected_file_path, new_path)
                selected_files.clear()
                selected_files.add(new_path)
                load_files(current_path)
                messagebox.showinfo("Success", f"File has been renamed to {new_name}")

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
            icon_key = 'file'  # Default icon key
            if ext in ['.txt']:
                icon_key = 'txt'
            elif ext in ['.pdf']:
                icon_key = 'pdf'
            elif ext in ['.jpg', '.jpeg', '.png']:
                icon_key = 'image'
            elif ext in ['.doc', '.docx']:
                icon_key = 'doc'
            elif ext in ['.ppt', '.pptx']:
                icon_key = 'ppt'
            elif ext in ['.xls', '.xlsx']:
                icon_key = 'xls'
            elif ext in ['.mp3', '.wav']:
                icon_key = 'audio'
            elif ext in ['.mp4', '.mkv']:
                icon_key = 'video'
            elif ext in ['.zip', '.rar']:
                icon_key = 'zip'

            if os.path.isdir(filepath):
                icon_key = 'folder'

            img = image_cache.get(icon_key, image_cache['file'])
            icon_label = Label(file_display_frame, image=img, text=file, compound="top", bg="#1e1e1e", fg="white",
                               font=('Arial', 12, 'bold'))
            icon_label.image = img
            icon_label.grid(row=row, column=col, padx=20, pady=20)
            icon_label.bind("<Button-1>", lambda e, p=filepath: on_select_file(e, p))
            if os.path.isdir(filepath):
                icon_label.bind("<Double-1>", lambda e, p=filepath: view_folder(p))
            col += 1

    def on_select_file(event, filepath):
        global selected_files, move_mode
        if not move_mode:
            if event.state & 0x0001:  # Shift key is held down
                if filepath in selected_files:
                    selected_files.remove(filepath)
                    event.widget.config(bg="#1e1e1e", fg="white")
                else:
                    selected_files.add(filepath)
                    event.widget.config(bg="blue", fg="yellow")
            else:
                if filepath in selected_files:
                    selected_files.remove(filepath)
                    event.widget.config(bg="#1e1e1e", fg="white")
                else:
                    selected_files.add(filepath)
                    event.widget.config(bg="blue", fg="yellow")
            move_button.config(state=NORMAL if selected_files else DISABLED)

    def view_folder(path):
        global current_path, move_mode
        current_path = path
        load_files(current_path)
        back_button.config(state=NORMAL, bg="red")
        if move_mode:
            move_button.config(state=NORMAL)

    def back():
        global current_path, move_mode
        parent_dir = os.path.dirname(current_path)
        user_dir = os.path.join(STORAGE_DIR, f"{current_user}_dir")
        if parent_dir.startswith(user_dir):
            current_path = parent_dir
            load_files(current_path)
            if current_path == user_dir:
                back_button.config(state=DISABLED, bg="gray")
        else:
            back_button.config(state=DISABLED, bg="gray")
        if move_mode:
            move_button.config(state=NORMAL)

    def delete_file():
        if selected_files:
            for file in selected_files:
                os.remove(file)
            load_files(current_path)
            messagebox.showinfo("Success", "Selected files have been deleted")
            selected_files.clear()

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
                with open(filename, 'rb') as file:
                    file_data = file.read()
                encrypted_data = encrypt(file_data, KEY)
                destination = os.path.join(current_path, os.path.basename(filename))
                with open(destination, 'wb') as fdst:
                    fdst.write(encrypted_data)
                load_files(current_path)
                messagebox.showinfo("Success", "File has been uploaded and encrypted successfully")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")

    def download_file():
        if selected_files:
            downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
            for selected_file_path in selected_files:
                save_path = os.path.join(downloads_folder, os.path.basename(selected_file_path))
                try:
                    with open(selected_file_path, 'rb') as fsrc:
                        encrypted_data = fsrc.read()
                    try:
                        decrypted_data = decrypt(encrypted_data, KEY)
                        with open(save_path, 'wb') as fdst:
                            fdst.write(decrypted_data)
                        messagebox.showinfo("Success",
                                            f"File has been decrypted and downloaded to {save_path} successfully")
                    except ValueError as e:
                        messagebox.showerror("Error", "Decryption failed. Invalid padding bytes.")
                except Exception as e:
                    messagebox.showerror("Error", f"An error occurred: {e}")

    def move_file():
        global selected_files, move_mode, current_path

        def disable_buttons():
            refresh_button.config(state=DISABLED)
            delete_button.config(state=DISABLED)
            rename_button.config(state=DISABLED)
            create_folder_button.config(state=DISABLED)
            upload_button.config(state=DISABLED)
            download_button.config(state=DISABLED)
            send_button.config(state=DISABLED)
            receive_button.config(state=DISABLED)

        def enable_buttons():
            refresh_button.config(state=NORMAL)
            delete_button.config(state=NORMAL)
            rename_button.config(state=NORMAL)
            create_folder_button.config(state=NORMAL)
            upload_button.config(state=NORMAL)
            download_button.config(state=NORMAL)
            send_button.config(state=NORMAL)
            receive_button.config(state=NORMAL)
            if current_path == os.path.join(STORAGE_DIR, f"{current_user}_dir"):
                back_button.config(state=DISABLED, bg="gray")
            else:
                back_button.config(state=NORMAL, bg="red")

        if not move_mode and selected_files:
            move_mode = True
            move_button.config(text="Move Here")
            disable_buttons()
        elif move_mode and selected_files:
            try:
                for file in selected_files:
                    shutil.move(file, os.path.join(current_path, os.path.basename(file)))
                selected_files.clear()
                move_mode = False
                move_button.config(text="Move")
                load_files(current_path)
                enable_buttons()
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")


    button_frame = Frame(root, bg="#1e1e1e")
    button_frame.pack(pady=10)

    refresh_button = Button(button_frame, text="Refresh", width=10, height=1, bg="blue", fg="white", command=lambda: load_files(current_path))
    refresh_button.grid(row=0, column=0, padx=10)
    delete_button = Button(button_frame, text="Delete", width=10, height=1, bg="red", fg="white", command=delete_file)
    delete_button.grid(row=0, column=1, padx=10)
    rename_button = Button(button_frame, text="Rename", width=10, height=1, bg="yellow", fg="black", command=rename_file)
    rename_button.grid(row=0, column=2, padx=10)
    create_folder_button = Button(button_frame, text="Create Folder", width=12, height=1, bg="cyan", fg="black", command=create_folder)
    create_folder_button.grid(row=0, column=3, padx=10)
    upload_button = Button(button_frame, text="Upload", width=10, height=1, bg="purple", fg="white", command=upload_file)
    upload_button.grid(row=0, column=4, padx=10)
    download_button = Button(button_frame, text="Download", width=12, height=1, bg="orange", fg="black", command=download_file)
    download_button.grid(row=0, column=5, padx=10)
    move_button = Button(button_frame, text="Move", width=10, height=1, bg="brown", fg="white", command=move_file)
    move_button.grid(row=0, column=6, padx=10)
    send_button = Button(button_frame, text="Send", width=10, height=1, bg="green", fg="white", command=send_window)
    send_button.grid(row=0, column=7, padx=10)
    receive_button = Button(button_frame, text="Receive", width=10, height=1, bg="black", fg="white", command=receive_window)
    receive_button.grid(row=0, column=8, padx=10)
    back_button = Button(button_frame, text="Back", width=10, height=1, bg="gray", fg="white", command=back, state=DISABLED)
    back_button.grid(row=0, column=9, padx=10)

    file_display_frame = Frame(root, bg="#1e1e1e")
    file_display_frame.pack(fill=BOTH, expand=YES)
    load_files(current_path)

    root.mainloop()


# Application Starts Here
login_window()
