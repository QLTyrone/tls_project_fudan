import socket
import random
import time
from Crypto.Util.Padding import pad
from rsa import PublicKey
from txdpy import get_num
from Crypto.Cipher import DES
import rsa
import hashlib
from enum import Enum

class RcvType(Enum):
    rcv_hello = 0
    rcv_pub_key = 1
    rcv_hello_done = 2
    rcv_cipher_spec = 3
    rcv_finish = 4
    rcv_mac_res = 5

ServerName = "127.0.0.1"
ServerPort = 6068

# socket连接
cSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cSocket.connect((ServerName, ServerPort))


# 随机生成密钥
def get_key(n):
    c_length = int(n)
    source = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    length = len(source) - 1
    result = ''
    for i in range(c_length):
        result += source[random.randint(0, length)]
    return result


if __name__ == "__main__":
    # 用于记录tls握手的进度
    rcvTime = 0

    # 随机生成64位会话密钥
    sessionKey = get_key(8)

    # Client Hello：发送 Client Hello
    cSocket.send("Client Hello".encode('utf-8'))
    print("->Client Hello")

    while True:
        rcv = cSocket.recv(1024)

        # 接收到'Server Hello'
        if rcvTime == RcvType.rcv_hello.value:
            print(rcv.decode('utf-8'))
            time.sleep(0.2)
            rcvTime += 1

        # 接收到'Server_Key_Exchange'的pubkey
        elif rcvTime == RcvType.rcv_pub_key.value:
            pubkey = rcv.decode('utf-8')
            num = get_num(pubkey)   # 获取字符串中的数字字符串
            print("Server_Key_Exchange")
            cryptoKey = rsa.encrypt(sessionKey.encode('utf-8'), PublicKey(int(num[0]), int(num[1])))    # rsa用pubkey加密sessionkey得到cryptoKey
            time.sleep(0.2)
            rcvTime += 1

        # 接收到'Server_Hello_Done'
        elif rcvTime == RcvType.rcv_hello_done.value:
            print(rcv.decode('utf-8'))
            cSocket.send(cryptoKey)    #发送cryptoKey
            print(sessionKey)
            print("->Client_Key_Exchange")
            time.sleep(0.2)
            
            cSocket.send("Change_Cipher_Spec".encode('utf-8'))      #发送Change_Cipher_Spec
            print("->Change_Cipher_Spec")
            time.sleep(2)

            des = DES.new(sessionKey.encode('utf-8'), DES.MODE_ECB)      # 创建DES实例(sessionKey)
            cSocket.send(des.encrypt("finished".encode('utf-8')))   #发送DES加密后的finished
            time.sleep(1)
            print("->finished")
            rcvTime += 1

        # 收到Server发送来的'Change_Cipher_Spec'
        elif rcvTime == RcvType.rcv_cipher_spec.value:
            print(rcv.decode('utf-8'))
            time.sleep(0.2)
            rcvTime += 1

        # 收到Server发送来的'finished'
        # client与server均完成, 开始传输字符串与MAC
        elif rcvTime == RcvType.rcv_finish.value:
            print(des.decrypt(rcv).decode('utf-8'))
            time.sleep(0.2)
            print("\n会话密钥：", sessionKey)

            # 用DES加密并发送字符串
            plaintext = input("\n请输入客户端要发给服务器的字符串：")
            ciphertext = des.encrypt(pad(str.encode(plaintext), 16))
            cSocket.send(ciphertext)
            print("明文：", plaintext)
            print("密文：", ciphertext)
            time.sleep(1)

            # 用SHA256加密并发送MAC
            MAC = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
            print("MAC值：", MAC)
            cSocket.send(MAC.encode())
            time.sleep(0.2)
            print("->发送密文和MAC")
            rcvTime += 1

        # MAC验证结果
        elif rcvTime == RcvType.rcv_mac_res.value:
            print(des.decrypt(rcv).decode('utf-8'))
            break

    cSocket.close()
