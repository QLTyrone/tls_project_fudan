import hashlib
import socket
import time
import rsa
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad, pad
from enum import Enum

class RcvType(Enum):
    rcv_hello = 0
    rcv_get_key = 1
    rcv_cipher_spec = 2
    rcv_finish = 3
    rcv_encryprion_txt = 4
    rcv_mac = 5

ServerPort = 6068

# 建立连接
ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ServerSocket.bind(('', ServerPort))
ServerSocket.listen(1)

if __name__ == "__main__":
    sSocket, addr = ServerSocket.accept()

    # 随机生成server的公私钥
    (pubkey, privkey) = rsa.newkeys(1024)

    # 用于记录tls握手的进度
    rcvTime = 0

    while True:
        rcv = sSocket.recv(1024)  #接收数据包

        # 收到'Client Hello'
        if rcvTime == RcvType.rcv_hello.value:
            print(rcv.decode())
            sSocket.send("Server Hello".encode('utf-8'))     #Server Hello
            print("->Server Hello")
            time.sleep(0.2)

            # 发送公钥
            sSocket.send(str(pubkey).encode('utf-8'))    #Server_Key_Exchange
            print("->Server_Key_Exchange")
            time.sleep(0.2)

            sSocket.send("Sever_Hello_Done".encode('utf-8')) #Server_Hello_Done
            print("->Sever_Hello_Done")
            time.sleep(0.2)
            rcvTime += 1

        # 收到加密后的sessionkey，用私钥解密
        elif rcvTime == RcvType.rcv_get_key.value:
            sessionKey = rsa.decrypt(rcv, privkey)  #私钥解密
            print(sessionKey)
            des = DES.new(sessionKey, DES.MODE_ECB)
            time.sleep(0.2)
            rcvTime += 1

        # 收到Client发送的'Change_Cipher_Spec'
        elif rcvTime == RcvType.rcv_cipher_spec.value:
            print(rcv)
            time.sleep(0.2)
            rcvTime += 1

        # 收到Client发送的'finished'
        elif rcvTime == RcvType.rcv_finish.value:
            print(des.decrypt(rcv).decode('utf-8'))
            sSocket.send("Change_Cipher_Spec".encode('utf-8'))
            print("->Change_Cipher_Spec")
            time.sleep(2)

            sSocket.send(des.encrypt("finished".encode('utf-8')))   #发送DES加密后的finished
            print("->finished")
            time.sleep(1)

            print("\n会话密钥：", sessionKey)
            rcvTime+=1

        # 字符串解密
        elif rcvTime == RcvType.rcv_encryprion_txt.value:
            print("\n接收到的字符串：")
            print("密文：", rcv)
            rcv_txt = unpad(des.decrypt(rcv),16)                  ##DES解密去掉补位
            print("明文：", rcv_txt.decode('utf-8'))
            rcvTime += 1

        # MAC值验证
        elif rcvTime == RcvType.rcv_mac.value:
            rcv_MAC = rcv.decode()
            print("接收到的MAC值：", rcv_MAC)
            MAC = hashlib.sha256(rcv_txt).hexdigest()
            print("计算出的MAC值：", rcv_MAC)
            if MAC == rcv_MAC:
                respond = pad(str.encode("MAC verify success"), 16)
                print("MAC verify success")
            else:
                respond = pad(str.encode("MAC Verify fail. Please resent."), 16)
                print("MAC verify fail")
            sSocket.send(des.encrypt(respond))
            time.sleep(1)
            break
    ServerSocket.close()




