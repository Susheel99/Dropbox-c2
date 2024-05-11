# Dropbox C2

## Overview

This README provides an overview of a Command and Control (C2) system implementation utilizing Python scripts (`client.py` and `server.py`) for secure communications and operations management through Dropbox.

### Core Functionality

- `client.py` and `server.py` scripts constitute the core of the C2 infrastructure, facilitating remote command execution, file uploads, and persistent access management on compromised systems.
- Both scripts utilize Dropbox as a medium for command exchange and output retrieval, leveraging Dropbox's API for secure uploads and downloads.

## Key Features

### Encryption

- AES-128 in CBC mode is employed for message encryption and decryption, ensuring secure data transmission.

### File Handling

- The client script facilitates data exfiltration, with a specific focus on Chrome cookies, which are uploaded to Azure Blob Storage.

### Persistence

- Methods are implemented to maintain persistence on compromised machines, ensuring sustained access.

## `client.py`

- Manages various functionalities, including decrypting and executing commands from the server, accessing and uploading Chrome cookies, and downloading and executing DLLs for persistence.
- Monitors the Dropbox file for new commands, decrypts them, and executes them sequentially.

## `server.py`

- Provides an interface for the operator to securely send commands to the client.
- Encrypts commands before sending and decrypts responses received from the client.
- Regularly checks and displays outputs from the client, facilitating real-time interaction and monitoring.

## C2 Commands

You can execute various commands using the normal Windows shell, as well as special C2 commands for data exfiltration and persistence.

### Windows Shell Commands

You can execute typical Windows shell commands using the C2 infrastructure.

### Special C2 Commands

- **`get_cookies`**: Decrypts the Chrome cookies and uploads them to the Azure Blob container.
- **`persist_dll`**: Uses DLL Hijacking technique to achieve persistence.
- **`persist_reg`**: Adds a registry key to achieve persistence.
- **`exit`**: Terminates the client and server.

## Security and Usage

- Encryption keys and Dropbox API tokens are hardcoded, which is not recommended for production environments. These should be securely managed and stored in environment variables or secure key management systems.
- The system is capable of executing arbitrary commands on the client machine, which makes it powerful but also potentially harmful if misused.

## Legal and Ethical Notice

- This system is intended for educational purposes or legitimate use in penetration testing scenarios with authorized consent only.
- Misuse of this technology can violate privacy rights and laws. Users must ensure they comply with all applicable laws and ethical guidelines.

## Setup Instructions

1. Ensure Python and necessary packages are installed.
2. Configure Dropbox API tokens and adjust paths as necessary.
3. Run `server.py` to start sending commands and `client.py` on the client machine to start receiving and executing commands.

This documentation ensures that users can effectively set up and operate the C2 system while understanding the implications and responsibilities that come with its deployment.
