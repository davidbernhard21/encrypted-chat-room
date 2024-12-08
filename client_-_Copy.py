import os

# from saber import kem
from saber.utils.constans import CONSTANTS_LIGHT_SABER
from saber.utils.algorithms import randombytes
from Crypto.Cipher import AES
from saber.pke import PKE
from saber.kem import KEM

# The Tcl library is part of the Tcl (Tool Command Language) ecosystem.
# Tcl is a high-level, interpreted scripting language that is known for its simplicity and flexibility.
# The Tcl library, often referred to as tcllib,
# is a collection of modules and packages that extend the functionality of the core Tcl language.
os.environ['TCL_LIBRARY'] = r'C:\Users\David\AppData\Local\Programs\Python\Python313\tcl\tcl8.6'

# import all the required modules
import sys
import socket
import threading
# Tkinter is the standard GUI (Graphical User Interface) library included with most Python installations.
# It provides tools for creating desktop applications with graphical interfaces,
# allowing developers to build windows, dialogs, buttons, and other interactive elements.
from tkinter import *
from tkinter import font
from tkinter import ttk
from tkinter import messagebox
from matplotlib.colors import is_color_like
from matplotlib.colors import to_hex
from Crypto.Cipher import ChaCha20

#from Crypto.Cipher import AES
#from Crypto.Util.Padding import unpad
#from Crypto.Util.Padding import pad

PORT = 8081
SERVER = '127.0.0.1'
ADDRESS = (SERVER, PORT)

chakey = b'12345678901234567890123465790123'  # key should be 32 bytes
aeskey = b'mysecretpassword'  #16 byte password
receivedChakey = b'empty'

# Create a new client socket and connect to the server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


# GUI class for the chat
class GUI:
    # constructor method
    def __init__(self):

        # Define the PKE class
        kem = KEM(**CONSTANTS_LIGHT_SABER)
        # Step 1: Generate key pairs for both clients
        public_key_A, secret_key_A = kem.KeyGen()
        print("Key Pair")
        print(public_key_A)
        print(secret_key_A)
        public_key_B, secret_key_B = kem.KeyGen()
        print(public_key_B)
        print(secret_key_B)

        # Step 2: Client A encapsulates a symmetric key for Client B
        session_key_alice, ciphertext = kem.Encaps(public_key_B)
        print("Chiper Text")
        print(ciphertext)

        # Step 3: Client B decapsulates the symmetric key
        session_key_bob  = kem.Decaps(ciphertext, secret_key_B)
        print("Shared Secred B")
        print(session_key_bob )

        # Verify that both shared secrets are identical
        assert session_key_alice == session_key_bob

        # Convert shared secret to a 32-byte key for ChaCha20
        symmetric_key = session_key_alice[:32] # Take the first 32 bytes
        print("Symmetric key")
        print(symmetric_key)

        # chat window which is currently hidden
        self.Window = Tk()
        self.Window.withdraw()

        def on_closing():
            if messagebox.askokcancel("Quit", "Do you want to quit?"):
                self.Window.destroy()
                client.close()

        # login window
        self.login = Toplevel()
        # set the title
        self.login.title("Login")
        self.login.resizable(width=False, height=False)
        self.login.configure(width=400, height=300)
        # create a Label
        self.pls = Label(self.login,
                         text="Please login to continue",
                         justify=CENTER,
                         font="BookAntiqua 12")

        self.pls.place(relheight=0.15, relx=0.2, rely=0.07)
        # create a Label
        self.labelName = Label(self.login,
                               text="Name: ",
                               font="BookAntiqua 12")

        self.labelName.place(relheight=0.2, relx=0.1, rely=0.2)

        # create a entry box for
        # typing the message
        self.entryName = Entry(self.login, font="BookAntiqua 12")
        self.entryName.place(relwidth=0.4, relheight=0.12, relx=0.35, rely=0.2)

        self.labelRoomName = Label(self.login,
                                   text="Room: ",
                                   font="BookAntiqua 12")

        self.labelRoomName.place(relheight=0.2, relx=0.1, rely=0.4)

        self.roomName = Entry(self.login, font="BookAntiqua 12")
        self.roomName.place(relwidth=0.4, relheight=0.12, relx=0.35, rely=0.4)

        self.labelRoomColor = Label(self.login,
                                    text="Room color: ",
                                    font="BookAntiqua 12")

        self.labelRoomColor.place(relheight=0.2, relx=0.1, rely=0.6)

        self.roomColor = Entry(self.login, font="BookAntiqua 12")
        self.roomColor.place(relwidth=0.4, relheight=0.12, relx=0.35, rely=0.6)

        # set the focus of the cursor
        self.entryName.focus()

        # create a Continue Button
        # along with action
        self.go = Button(self.login,
                         text="Continue",
                         font="BookAntiqua 12",
                         command=lambda: self.createRoom(self.entryName.get(
                         ), self.roomName.get(), self.roomColor.get()))

        self.go.place(relx=0.4, rely=0.8)
        self.Window.protocol("WM_DELETE_WINDOW", on_closing)
        self.login.protocol("WM_DELETE_WINDOW", on_closing)
        self.Window.mainloop()

    def createRoom(self, name, room, color):
        self.login.destroy()
        print('here we go, chat room is created')
        room = room.upper()

        if not name or not room:
            print('name/room is missing')
            messagebox.showerror("showerror", "Invalid Name/Room entered.")
            sys.exit(1)

        if not is_color_like(color):
            print('room color is not valid')
            messagebox.showerror("showerror", "Invalid Room color entered.")
            sys.exit(1)

        if to_hex(color) == '#000000':
            messagebox.showwarning(
                "showwarning",
                "Black is not an acceptable Room color.\nRoom color set to White."
            )
            color = "White"

        self.layout(name, room, color)

        client.connect(ADDRESS)

        # Test connect to the server
        # try:
        #     client.connect(ADDRESS)
        #     print("Connected to server successfully")
        # except ConnectionRefusedError:
        #     print("Connection refused by the server")
        # except Exception as e:
        #     print(f"Error: {e}")

        client.send(room.encode())
        response = client.recv(10)
        if response == b'ok':
            client.send(name.encode())
            client.recv(10)
            joined = (f"[{name}] HAS JOINED THE CHAT!{chakey.decode()}").encode()
            left = (f"[{name}] HAS LEFT THE CHAT!").encode()
            # client.send(joined.encode())

            # chacha20 encryption
            cipher = ChaCha20.new(key=chakey)
            print(f"[{cipher}] ChaCha20 Object Cipher One")
            ciphertext = cipher.encrypt(joined)
            print(f"Joined text after encrypt: [{ciphertext}] with ChaCha20")
            client.send(cipher.nonce + ciphertext)
            print(f"Nonce + joined text after encrypt: [{cipher.nonce + ciphertext}]")
            client.recv(10)

            cipher2 = ChaCha20.new(key=chakey)
            # print(f"Left text before encrypt: [{cipher2}] ChaCha20 Object Cipher Two")
            ciphertext2 = cipher2.encrypt(left)
            # print(f"Left text after encrypt: [{ciphertext2}] ChaCha20 Cipher Text Two")
            client.send(cipher2.nonce + ciphertext2)
            # print(f"Nonce + left text after encrypt: [{cipher2.nonce + ciphertext2}] ChaCha20 Send Two")
            client.recv(10)

            # the thread to receive messages
            rcv = threading.Thread(target=self.receive)
            rcv.start()
            print('start listening')
        else:
            print('Could not connect')
            messagebox.showwarning("showwarning",
                                   "The Room you entered does not exist.")
            sys.exit(1)

    # The main layout of the chat
    def layout(self, name, room, color):

        self.name = name
        self.room = room
        self.color = color
        # to show chat window
        self.Window.deiconify()
        self.Window.title("Chatroom")
        self.Window.resizable(width=False, height=False)
        self.Window.configure(width=470, height=550, bg='Black')
        self.labelHead = Label(self.Window,
                               bg="gray38",
                               fg="snow",
                               text=self.room,
                               font="BookAntiqua 12",
                               pady=5)

        self.labelHead.place(relwidth=1)
        self.line = Label(self.Window, width=450, bg="#ABB2B9")

        self.line.place(relwidth=1, rely=0.07, relheight=0.012)

        self.textCons = Text(self.Window,
                             width=20,
                             height=2,
                             bg=self.color,
                             fg="gray1",
                             font="BookAntiqua 12",
                             padx=5,
                             pady=5)

        self.textCons.place(relheight=0.745, relwidth=1, rely=0.08)

        self.labelBottom = Label(self.Window, bg="#ABB2B9", height=80)

        self.labelBottom.place(relwidth=1, rely=0.825)

        self.entryMsg = Entry(self.labelBottom,
                              bg='snow',
                              fg='gray1',
                              font="BookAntiqua 12")

        # place the given widget
        # into the gui window
        self.entryMsg.place(relwidth=0.74,
                            relheight=0.06,
                            rely=0.008,
                            relx=0.011)

        self.entryMsg.focus()

        # create a Send Button
        self.buttonMsg = Button(
            self.labelBottom,
            text="Send",
            font="Helvetica 10 bold",
            width=20,
            bg="#ABB2B9",
            command=lambda: self.sendButton(self.entryMsg.get()))

        self.buttonMsg.place(relx=0.77,
                             rely=0.008,
                             relheight=0.06,
                             relwidth=0.22)

        self.textCons.config(cursor="arrow")

        # create a scroll bar
        scrollbar = Scrollbar(self.textCons)

        # place the scroll bar
        # into the gui window
        scrollbar.place(relheight=1, relx=0.974)

        scrollbar.config(command=self.textCons.yview)

        self.textCons.config(state=DISABLED)

    # function to basically start the thread for sending messages
    def sendButton(self, msg):
        self.textCons.config(state=DISABLED)
        self.msg = msg
        self.entryMsg.delete(0, END)
        snd = threading.Thread(target=self.sendMessage)
        snd.start()

    # function to receive messages
    def receive(self):
        global receivedChakey
        while True:
            try:
                data = client.recv(4096)

                #encryption_len = 16  # for aes
                encryption_len = 8  # for chacha20

                # if there is at least 1 byte encrypted
                if data and len(data) > encryption_len + 1:

                    # chacha20 decryption
                    nonce = data[:encryption_len]  # 8 bytes for the nonce
                    ciphertext = data[
                                 encryption_len:]  # the rest of the data is encrypted

                    if receivedChakey == b'empty': # new guest joined chatroom
                        cipher = ChaCha20.new(key=chakey, nonce=nonce)
                    else: # existing guest send message
                        cipher = ChaCha20.new(key=receivedChakey, nonce=nonce)

                    # cipher = ChaCha20.new(key=chakey, nonce=nonce)
                    print(f"Nonce + received message: [{nonce + ciphertext}] Received Encrypted Message with ChaCha20")
                    message = cipher.decrypt(ciphertext)
                    message = message.decode(errors="ignore")
                    splittedMessage = message.split('!')
                    print(f"Splitted message: [{splittedMessage}]")
                    if len(splittedMessage) > 1:
                        receivedChakey = splittedMessage[1].encode()
                    print(f"Decoded message: [{message}]")

                    # aes decryption
                    #iv = data[:encryption_len]  # 16 bytes for the iv
                    #ciphertext = data[encryption_len:]
                    #cipher = AES.new(aeskey, AES.MODE_CBC, iv)
                    #message = unpad(cipher.decrypt(ciphertext), AES.block_size)
                    #message = message.decode()

                    # insert messages to text box
                    self.textCons.config(state=NORMAL)
                    self.textCons.insert(END, message + "\n\n")

                    self.textCons.config(state=DISABLED)
                    self.textCons.see(END)
            except socket.error:
                # print('Connection error')
                client.close()
                break
            except EXCEPTION as e:
                # an error will be printed on the command line or console if there's an error
                print("An error occurred!")
                print(f"Error: {e}")
                # continue

    # function to send messages
    def sendMessage(self):
        self.textCons.config(state=DISABLED)

        message = (f"{self.name}: {self.msg}").encode()

        try:
            # chacha20 encryption
            print(f"Current ChaCha20 key: [{receivedChakey}]")
            cipher = ChaCha20.new(key=receivedChakey)
            ciphertext = cipher.encrypt(message)
            client.send(cipher.nonce + ciphertext)
            print(f"Nonce + sent message: [{cipher.nonce + ciphertext}] Sent Encrypted Message with ChaCha20")

            # aes encryption
            #cipher = AES.new(aeskey, AES.MODE_CBC)
            #ciphertext = cipher.encrypt(pad(message, AES.block_size))
            #client.send(cipher.iv + ciphertext)
        except BrokenPipeError:
            print('Server is down')
            self.Window.destroy()


# create a GUI class object
g = GUI()