# CipherCrusader
## Summary
CipherCrusader is an open-source command-line password manager created in Python 3.9. The program requires Python 3.9 or later to be installed on the user's device. Instructions on how to install Python can be found on the official Python website (https://www.python.org/).

CipherCrusader utilizes AES encryption to secure the user's login information stored in an SQLite database. The database is encrypted by default and can only be accessed by providing the correct password. The program locks out the user after 60 seconds of inactivity. When locked, most features require the master password. After 3 failed password attempts, the program exits to prevent brute-force attacks.

CipherCrusader offers a variety of commands for the user to manage their login information. These include:
- `generate`: Generates a strong, unique password of a user-specified length.
- `add`: Adds an entry to the database, including a website, username, and password.
- `remove`: Removes an entry from the database.
- `get`: Retrieves the credentials for a specified website.
- `copy`: Copies the password for a specified website.
- `list`: Lists all websites for which the user has stored credentials in the database.
- `resetpw`: Resets the master password after authenticating the user.
- `exit`: Encrypts the database and exits the program.
- `help`: Lists all available commands and their functions.

The first time the program is run, the program will ask the user for a name for the database which will be created in the program's directory. When encrypted, the file extension will change to '.db.enc'.
## Installation:
1. Make sure you have Python 3.9 or later installed on your device. If you don't have Python installed, you can download it from the official Python website (https://www.python.org/).

2. Download the source code for CipherCrusader from the repository.

3. Install the dependencies listed in the requirements.txt file by running the following command:
    ```
    pip install -r requirements.txt
    ```

4. Run the script using the command:
    ```
    python CipherCrusader.py
    ```
## Issues/Contributing
If you encounter any issues or bugs with the program, please feel free to submit an issue or submit a pull request with your suggested changes.

#### Thank you for using CipherCrusader and have a great day! ☺️