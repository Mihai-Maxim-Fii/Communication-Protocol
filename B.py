import socket
import argparse
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Util.strxor import strxor
import binascii
HOST = '127.0.0.1'
PORTSERVER = 5001
PORTNODE=5000
key=b''
Message=b''
initVector=b'8\x9b\x1e\ri7\x02\x9e\x7fz\xb4/gt\x8a='
K3=b"\x9e\xa8\x81-\x13D\x87\xae!\xb3c\xa6\x8a\x97\x1bF"
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORTNODE))
    s.listen()
    conn, addr = s.accept()
    with conn:
            print('Connected by', addr)
            dataNode = conn.recv(1024)
            print(dataNode)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((HOST, PORTSERVER))
                sock.sendall(dataNode)
                key = sock.recv(1024)
                cipher = AES.new(K3, AES.MODE_ECB)
                key=cipher.decrypt(key)
            conn.sendall(b'Ready')
            if dataNode.decode('utf-8')=='ECB':
                cipher = AES.new(key, AES.MODE_ECB)
                while True:
                 messageBlock=conn.recv(16)
                 if messageBlock.hex()=='446f6e65':
                     break
                 msg=cipher.decrypt(messageBlock)
                 if msg.__contains__(b'\x0b'):
                    Message+=unpad(msg,16)
                 else:
                     Message+=msg
            if dataNode.decode('utf-8')=='CBC':
                cipher = AES.new(key, AES.MODE_ECB)
                firstRun = True
                crt=b''
                while True:
                    messageBlock = conn.recv(16)
                    if messageBlock.hex() == '446f6e65':
                        break
                    msg = cipher.decrypt(messageBlock)
                    msg = bytearray(msg)
                    if firstRun:
                     strxor(msg,initVector,msg)
                     firstRun=False
                    else:
                     strxor(msg,crt,msg)
                    crt=messageBlock
                    if msg.__contains__(b'\x0b'):
                        msg = unpad(msg, 16)
                    messageBlock=msg
                    Message+=messageBlock


    print(Message)




