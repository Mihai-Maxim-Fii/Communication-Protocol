import socket
import selectors
import types
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
HOST = '127.0.0.1'
PORT = 5001

K3=b"\x9e\xa8\x81-\x13D\x87\xae!\xb3c\xa6\x8a\x97\x1bF"
ECB=get_random_bytes(16)
CBC=get_random_bytes(16)
import socket

from _thread import *
import threading

print_lock = threading.Lock()


def threaded(c):
    while True:
        data = c.recv(1024)
        if not data:
            print('Bye')
            print_lock.release()
            break
        cipher = AES.new(K3, AES.MODE_ECB)
        if data.decode("utf-8") == 'ECB':
            ciphertext = cipher.encrypt(ECB)
        else:
            ciphertext = cipher.encrypt(CBC)

        c.send(ciphertext)
    c.close()


def Main():
    host = "127.0.0.1"
    port = 5001
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    print("socket binded to port", port)
    s.listen(100)
    print("socket is listening")
    while True:
        c, addr = s.accept()
        print_lock.acquire()
        print('Connected to :', addr[0], ':', addr[1])
        start_new_thread(threaded, (c,))
    s.close()


Main()



