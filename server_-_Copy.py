import os
import sys
# import socket library
import socket

# from saber import kem
from saber.utils.constans import CONSTANTS_LIGHT_SABER
from saber.utils.algorithms import randombytes
from Crypto.Cipher import AES
from saber.pke import PKE
from saber.kem import KEM

# import threading library
import threading
import time

# Choose a port that is free
PORT = 8081

# An IPv4 address for the server.
SERVER = '127.0.0.1'

# Address is stored as a tuple
ADDRESS = (SERVER, PORT)

# the format in which encoding and decoding will occur
FORMAT = "utf-8"

# Lists that will contain all the clients/rooms connected to the server.
rooms = {'GENERAL': {}, 'SCHOOL': {}, 'TRY': {}}

# Create a new socket for the server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# bind the address of the server to the socket
server.bind(ADDRESS)


# function to start the connection
def startServer():
    print("server is working on " + SERVER + " : " + str(PORT))

    # listening for connections
    server.listen()

    while True:
        # accept connections and returns
        # a new connection to the client
        # and the address bound to it
        conn, addr = server.accept()

        # receive room name
        room = conn.recv(64).decode()
        if room in rooms:  # if room exists
            conn.send(b'ok')  # send acknowledgment

            # append the client
            # to the respective list
            rooms[room][addr[0] + str(addr[1])] = conn

            name = conn.recv(64).decode()
            conn.send(b'ok')  # send acknowledgment
            joined = conn.recv(4096)
            conn.send(b'ok')  # send acknowledgment
            left = conn.recv(4096)
            conn.send(b'ok')  # send acknowledgment

            # Start the handling thread
            thread = threading.Thread(target=handle,
                                      args=(conn, addr, room, name, joined,
                                            left))
            thread.start()

            # no. of clients connected to the server
            print(f"active connections {threading.active_count() - 1}")

        else:
            print('Room does not exist.')
            conn.close()


# incoming messages
def handle(conn, addr, room, name, joined, left):
    print(f"Received publicKey: {joined}")

    # Server encapsulates a symmetric key for Client
    kem = KEM(**CONSTANTS_LIGHT_SABER)

    start_time = time.perf_counter()
    # print(f"Start Encryption Time: {start_time:.7f} seconds")
    secretKey, ciphertext = kem.Encaps(joined)
    end_time = time.perf_counter()
    # print(f"End Encryption Time: {end_time:.7f} seconds")
    elapsed_time_seconds = end_time - start_time
    print(f"Elapsed Send Saber Encryption Time: {elapsed_time_seconds:.7f} seconds")

    print(f"Secret Key from Server: {secretKey}")
    print(f"Cipher Text send to Client: {ciphertext}")
    broadcastMessage(ciphertext, room)
    print(f"new connection {addr} = {name} to {room}.\n")
    while True:
        try:
            # receive message
            message = conn.recv(4096)
            print(f"Received message: {message}")
            # broadcast message
            broadcastMessage(message, room)
        except:
            break

    # close the connection
    conn.close()

    # remove the client from the clients list
    del rooms[room][addr[0] + str(addr[1])]
    # print(f"active connections {threading.activeCount() - 2}")
    print(f"{name} has disconnected")
    broadcastMessage(left, room)


# method for broadcasting
# messages to each client
def broadcastMessage(message, room):
    for addr in rooms[room]:
        rooms[room].get(addr).send(message)


# begin the communication
try:
    startServer()
except KeyboardInterrupt:
    server.close()
    server.close()
except:
    server.close()
    sys.exit(0)