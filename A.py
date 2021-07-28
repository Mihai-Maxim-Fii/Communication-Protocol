import socket
import argparse
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Util.strxor import strxor
import binascii
ECB=b'ECB'
CBC=b'CBC'
KEY='1'
HOST='127.0.0.1'
PORTSERVER=5001
PORTNODE=5000
K3=b'\x9e\xa8\x81-\x13D\x87\xae!\xb3c\xa6\x8a\x97\x1bF'
initVector=b'8\x9b\x1e\ri7\x02\x9e\x7fz\xb4/gt\x8a='
parser=argparse.ArgumentParser(description="This is node A")
parser.add_argument('--mode',metavar="mode",type=str,nargs='?')
args=parser.parse_args()
print(f"You are using: {args.mode}")
BLOCK_SIZE=16
n=32
cipher = AES.new(K3, AES.MODE_ECB)
data=b"This is the message to be sent! This is the message to be sent! This is the message to be sent! ".hex()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((HOST, PORTNODE))
    if(args.mode=='CBC'):
        sock.sendall(CBC)
    else:
        sock.sendall(ECB)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORTSERVER))
        if (args.mode == 'CBC'):
            s.sendall(CBC)
        else:
            s.sendall(ECB)

        KEY = s.recv(1024)
        KEY=cipher.decrypt(KEY)
    readyMessage = sock.recv(1024)
    if readyMessage.decode("utf-8")=='Ready':
        cipher = AES.new(KEY, AES.MODE_ECB)
        if(args.mode=='CBC'):
            cpt=b''
            firstRun=True
            for dt in [data[i:i + n] for i in range(0, len(data), n)]:
                    if (len(dt) < 32):
                     dt1=pad(bytes.fromhex(dt), BLOCK_SIZE)
                    else:
                     dt1=bytes.fromhex(dt)
                    dt2=bytearray(dt1)
                    if firstRun:
                       strxor(dt1,initVector,dt2)
                       firstRun=False
                    else:
                        strxor(dt1,cpt,dt2)

                    dt1=dt2
                    ciphertext = cipher.encrypt(dt1)
                    sock.send(ciphertext)
                    print(ciphertext.hex())
                    cpt=ciphertext
            sock.sendall(b'Done')
        else:

            for dt in [data[i:i + n] for i in range(0, len(data), n)]:
                if (len(dt) < 32):
                    ciphertext = cipher.encrypt(pad(bytes.fromhex(dt), BLOCK_SIZE))
                    sock.send(ciphertext)
                    print(ciphertext.hex())
                else:
                    ciphertext = cipher.encrypt(bytes.fromhex(dt))
                    sock.send(ciphertext)
                    print(ciphertext.hex())

            sock.sendall(b'Done')





