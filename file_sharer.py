import os
import socket
from tkinter import *
from tkinter import filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Global variables to store images
send_image = None
receive_image = None
image_icon1 = None
Sbackground = None
Mbackground = None
Hbackground = None
logo = None
imageicon = None

# AES key and salt for encryption
KEY = b'0123456789abcdef'  # 16-byte key for AES-128
SALT = b'salt_12345678'    # 12-byte salt

def load_images():
    global send_image, receive_image, image_icon1, Sbackground, Mbackground, Hbackground, logo, imageicon
    send_image = PhotoImage(file="Images/send.png").subsample(8, 8)  # Adjust size
    receive_image = PhotoImage(file="Images/received.png").subsample(8, 8)  # Adjust size
    image_icon1 = PhotoImage(file="Images/send.png").subsample(4, 4)  # Adjust size

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

def main_window():
    global root
    root = Tk()
    root.title("Share Files")
    root.geometry("400x300")
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

    root.mainloop()

def Send():
    window = Toplevel(root)
    window.title("Send")
    window.geometry('400x300')
    window.configure(bg="#1e1e1e")
    window.resizable(False, False)

    def select_file():
        global filename
        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title='Select Image File')

    def sender():
        s = socket.socket()
        host = socket.gethostname()
        port = 8080
        s.bind((host, port))
        s.listen(1)
        print(host)
        print('waiting for any incoming connections....')
        conn, addr = s.accept()
        file = open(filename, 'rb')
        file_data = file.read()
        encrypted_data = encrypt(file_data, KEY)
        conn.send(encrypted_data)
        print("Data has been transmitted successfully!")

    window.iconphoto(False, image_icon1)
    host = socket.gethostname()
    Label(window, text=f'Your Device ID: {host}', font='Verdana 12 bold', bg='black', fg='white').place(x=0, y=0)
    Button(window, text=">Select the file to send", width=20, height=1, font='arial 14 bold', bg="yellow", fg="blue",
           command=select_file).place(x=80, y=120)
    Button(window, text="SEND", width=8, height=1, font='arial 14 bold', bg='#000', fg="#fff", command=sender).place(
        x=150, y=180)

    window.mainloop()

def Receive():
    main = Toplevel(root)
    main.title("Receive")
    main.geometry('400x300')
    main.configure(bg="#1e1e1e")
    main.resizable(False, False)

    def receiver():
        iD = senderID.get()
        filename1 = incoming_file.get()

        s = socket.socket()
        port = 8080
        s.connect((iD, port))
        encrypted_data = s.recv(1024)
        decrypted_data = decrypt(encrypted_data, KEY)
        file = open(filename1, 'wb')
        file.write(decrypted_data)
        file.close()
        print("File has been received successfully!")

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

    rr = Button(main, text="Receive", compound=LEFT, image=imageicon, width=13, bg="#39c790", font="arial 14 bold",
                command=receiver)
    rr.place(x=145, y=190)

    main.mainloop()

# Start the application
main_window()
