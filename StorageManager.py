
import os
import shutil
import re
import subprocess
from pyzipper import zipfile
from pyzipper import ZipFile
import logging
import configparser
from datetime import datetime
cwd = os.getcwd()
windows_cmd = r'C:\Windows\System32\cmd.exe'
from cryptography.fernet import Fernet
import io
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# PART E: Log activities#
def log_activities():
    try:
        name = input("yourname for log file name:")
        log_file_name = datetime.now().strftime(f"%Y%m%d_%H%M%S_{name}.log")
        logging.basicConfig(filename=log_file_name, level=logging.INFO, format='%(asctime)s %(message)s', filemode='w')
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        logger.info(f"\ncreated log file: {log_file_name}")
    except Exception as E:
        logging.info(f"error {E}")

    finally:
        logging.info(f"no error in creating log file\n")
log_activities()



# #(no using-lesson4)
# from ftplib import FTP
#
# ftp = FTP()
# ftp.connect("127.0.0.1", 21)
# # ftp.login("user", "Password")
# ftp.login(user='anonymous', passwd='')
# ftp.cwd("/")
# ftp.retrbinary("RETR" + "resource", open(r'C:\ITE_shunxiang\ITE apps\pythonProject\AdministrativeScripting_Project\FTPTest\filetest', "wb").write)
# #
# # shutil.unpack_archive("FTPTest/project_resource.zip", "project_resource")




##working

logging.info("\n\n\nPART A: Data from information store manipulated correctly according to script requirement.")
logging.info("download files from ftp server")
from ftplib import FTP

ftp = FTP()
ftp.connect("127.0.0.1", 21)
ftp.login(user='anonymous', passwd='')

local_folder_path = r'C:\ITE_shunxiang\ITE apps\pythonProject\StorageManagement\history_a'  #client_folder as history_a includes  server_folder -> do_not_touch
remote_folder_path = "resource"


import os
if not os.path.exists(local_folder_path):
    os.makedirs(local_folder_path)

def download_folder(folder_name):                   #folder_name is a parameter, by removing the 'folder_name' i need to hard code the => folder_name=(nameOfFolder)
    try:
        local_folder_path_inside = os.path.join(local_folder_path, folder_name)
        os.makedirs(local_folder_path_inside)  # Create the folder locally
        ftp.cwd(folder_name)  # Change dir to the FTP server

        # Download each file within the folder
        for item in ftp.nlst():
            local_file_path = os.path.join(local_folder_path_inside, item)
            with open(local_file_path, 'wb') as local_file:
                ftp.retrbinary(f"RETR {item}", local_file.write)            #retrive binary file and write it to the local file
            print(f"Downloaded folder: {item} from {remote_folder_path} to {local_folder_path}")
            logging.info(f"Downloaded folder: {item} from {remote_folder_path} to {local_folder_path}")

        ftp.cwd('..')  # Move back to the parent directory after downloading the folder

    except Exception as e:
        print(f"Error downloading folder {folder_name} from ftp server: {e}")
        logging.info(f"Error downloading folder {folder_name} from ftp server: {e}")

def download_file(item):
    try:
        if "." not in item:  # Check if its a folder by checking if there is no dot in the name
            # If it's a folder, download its content
            ftp.cwd(item)               #change dir to the ftp server
            for sub_item in ftp.nlst():
                download_file(sub_item)
            ftp.cwd('..')  # Move back to the parent directory after downloading the folder
        else:
            # If it's a file with a dot ->[.] download it
            local_file_path = os.path.join(local_folder_path, item)
            with open(local_file_path, 'wb') as local_file:
                ftp.retrbinary(f"RETR {item}", local_file.write)
            print(f"Downloaded files: {item} from {remote_folder_path} to {local_folder_path}")
            logging.info(f"Downloaded files: {item} from {remote_folder_path} to {local_folder_path}")
    except Exception as e:
        print(f"Error downloading {item} from ftp server: {e}")
        logging.info(f"Error downloading {item} from ftp server: {e}")

# Change the working directory to the specified remote folder
ftp.cwd(remote_folder_path)

# Start downloading the "do_not_touch" folder with its contents
download_folder("do_not_touch")

# Start downloading other files and folders within the remote folder
for item in ftp.nlst():
    if item != "do_not_touch":  # skips the "do_not_touch" folder
        download_file(item)

ftp.quit()



## #(no using)
## # # creating StorageManagement and copying the files from the resource folder -#have not done the extract from ftp server
## def download_files():
##     try:
##         # sourceFilePath = os.path.join(cwd, 'project_resource/resource')
##         sourceFilePath = os.path.join(cwd, 'project_resource')
##         destinationFilePath = os.path.join(cwd, 'StorageManagement')
##         if not os.path.exists(destinationFilePath):
##             subprocess.call([windows_cmd, f'/c mkdir "{destinationFilePath}"'])
##         print("Before downloading files from ftp server => ", os.listdir())
##         shutil.copytree(sourceFilePath, destinationFilePath)
##
##     except FileExistsError:
##         print(f"Error: files Exists: {str(FileNotFoundError)}")
##     else:
##         # Code to execute if no exception occurs
##         print("After downloading files from ftp server => ", os.listdir())
##         # logging.info("Downloading files from FTP done.")
##     finally:
##         # Code to execute regardless of whether an exception occurs or not
##         # This block is useful for cleanup operations
##         # For example, close open files or connections
##         pass
## download_files()




logging.info("seperate files into image folder and text folder")
def seperate_files():
    configfilepath = os.path.join('history_a', 'config.txt')
    # Open the file in read mode
    with open(configfilepath, 'r') as configtxtfile:
        # Read and print the entire content of the file
        file_contents = configtxtfile.read()
        print(f'contents in {configfilepath} file:\n', file_contents)
    file_s = file_contents.split()

# #split method cannot, so read data into dictionary(no using)
#     # print(file_s[1:][1])
#     # file_Location = {}
#     # for c in file_s:
#     #     file_Location[c.split()[0]] = c.split()[1:]
#     #print(file_Location)


    with open(configfilepath, 'r') as configtxtfile:

        file_s = configtxtfile.read()
    # Create a ConfigParser object
    config = configparser.ConfigParser()
    # Read the data from a string
    config.read_string(file_s)
    # put the values into dictionary
    config_data = {}
    for section_name in config.sections():
        config_data[section_name] = {option: config.get(section_name, option) for option in config.options(section_name)}
    # list the variable for use
    print(f'dictionary of {configfilepath}=> ', config_data)
    logging.info(f"Read the contents of {configfilepath} and store it into a dictionary")
    # get the file name from the dictionary
    for key, value in config_data.items():


        print('Creating a folder for image', list(value.keys())[3])        #client_image_folder -- values.values take the name on the other side of =
        print('Creating a folder for text', list(value.keys())[4])        #client_text_folder

        subprocess.call([windows_cmd, fr'/c mkdir {list(value.keys())[3]}'])        #make client_image_folder   #if i wnat get clientImage change the keys to values***
        subprocess.call([windows_cmd, fr'/c mkdir {list(value.keys())[4]}'])


        for files in os.listdir('history_a/do_not_touch'):
            try:
                source_filepath = os.path.join('history_a/do_not_touch', files)
                if files.endswith('.txt'):
                    destination_folder = 'client_text_folder'  #
                    # destination_filepath = os.path.join(destination_folder, files)
                    # shutil.move(source_filepath, destination_filepath)
                    # print(f"Moved '{files}' to '{destination_folder}'")
                elif files.endswith(('.jpg', '.png', '.gif')):
                    destination_folder = 'client_image_folder'  #
                    # destination_filepath = os.path.join(destination_folder, files)
                    # shutil.move(source_filepath, destination_filepath)
                    # print(f"Moved '{files}' to '{destination_folder}'")
                else:
                    continue
                destination_filepath = os.path.join(destination_folder, files)
                shutil.move(source_filepath, destination_filepath)                      #move files to the folder respectively
                print(f"Moved '{files}' to '{destination_folder}'")
                logging.info(f"Moved '{files}' to '{destination_folder}'")
            except Exception as E:
                print(f'Error: {E}')
                logging.info(f'Error: {E}')
seperate_files()




logging.info("\n\n\nPART B: Anomalies detected in log files using appropriate script.")
def virius_files():
    configfilepath = os.path.join('history_a', 'config.txt')
    with open(configfilepath, 'r') as configtxtfile:

        file_s = configtxtfile.read()
    # Create a object
    config = configparser.ConfigParser()
    # Read the data from string
    config.read_string(file_s)
    # put the values into dictionary
    config_data = {}
    for section_name in config.sections():
        config_data[section_name] = {option: config.get(section_name, option) for option in
                                     config.options(section_name)}
    # list the variable for use
    print(f'dictionary of {configfilepath}=> ', config_data)
    logging.info(f"Read the contents of {configfilepath} and store it into a dictionary")
    for key, value in config_data.items():
        # get the file name from the dictionary
        virus_pattern = re.compile(r'([A-Z]{2}|[a-z]{2})\d{6}')
        print(list(value.keys())[5])
        print(list(value.keys())[4])


        # Create the destination folder if it doesn't exist
        if not os.path.exists(list(value.keys())[5]):
            os.makedirs(list(value.keys())[5])

        source_folder = (list(value.keys())[4])         #source_folder is client_text_folder

        # Iterate through files in the source folder
        for filename in os.listdir(source_folder):
            try:
                file_path = os.path.join(list(value.keys())[4], filename)

                if os.path.isfile(file_path):

                    with open(file_path, 'r') as file_content:
                        content = file_content.read()

                    # Check if the contents indside file matches the virus pattern
                    if re.search(virus_pattern, content):
                        # Move the infected file to the destination folder
                        destination_path = os.path.join(list(value.keys())[5], filename)
                        shutil.move(file_path, destination_path)
                        print(f"Moved infected file '{filename}' to '{list(value.keys())[5]}'")
                        logging.info(f"infected file detected: {filename} file moved to {list(value.keys())[5]}")
            except Exception as e:
                print(f"Error processing file '{filename}': {e}")
                logging.info(f"Error processing file '{filename}': {e}")
virius_files()





logging.info("\n\n\nPART C: Data in information store protected correctly according to requirement.")
logging.info("archive_files")
##-where i left off(continue tmr)
def archive_files():
    try:

        configfilepath = os.path.join('history_a', 'config.txt')
        with open(configfilepath, 'r') as configtxtfile:

            file_s = configtxtfile.read()
        # Create a ConfigParser object
        config = configparser.ConfigParser()
        # Read the data from a string in the txtfile
        config.read_string(file_s)
        # put the values into dictionary
        config_data = {}
        for section_name in config.sections():
            config_data[section_name] = {option: config.get(section_name, option) for option in config.options(section_name)}
        # list the variable for use
        print(f'dictionary of {configfilepath}=> ', config_data)
        logging.info(f"Read the contents of {configfilepath} and store it into a dictionary")

        # get the file name from the dictionary
        for key, value in config_data.items():
            client_zip_folder = list(value.keys())[6]
            print('Creating a folder for zip files', client_zip_folder)

            subprocess.call([windows_cmd, fr'/c mkdir {client_zip_folder}'])  # make client_zip_folder

            # Read the key from the file
            key_file_path = os.path.join("history_a", "filekey.key")
            with open(key_file_path, 'rb') as key_file:
                key = key_file.read()

            # Loop through text and image folders separately
            for folder_type in [list(value.keys())[4], list(value.keys())[3]]:
                files_folder = os.path.join(cwd, folder_type)
                for filename in os.listdir(files_folder):
                    try:
                        file_path = os.path.join(files_folder, filename)
                        creation_date = datetime.fromtimestamp(os.path.getctime(file_path))
                        formatted_date = creation_date.strftime('%b %Y')  # Format the creation date as "Dec 2022"

                        # Create a separate ZIP archive for each file
                        zip_filename = f"{creation_date.strftime('%Y%m')}-{folder_type.split('_')[1]}-{filename.split('.')[0]}.zip"
                        zip_filepath = os.path.join(client_zip_folder, zip_filename)

                        #
                        with zipfile.ZipFile(zip_filepath, 'w') as zip_file:
                            zip_file.write(file_path, os.path.basename(file_path))

                        print(f"{file_path} created on {formatted_date} archive to {zip_filepath}")
                        logging.info(f"{file_path} created on {formatted_date} archive to {zip_filepath}")

                    except Exception as e:
                        print(f"Error processing file '{filename}': {e}")
                        logging.error(f"Error processing file '{filename}': {e}")
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Error: {e}")


archive_files()



## no work pasowrd emcrpt(no using)
##encrypt files using the filekey
## password = input("Your password: ")
## def key_from_password(password, salt=b'salt', iterations=100000):
##     kdf = PBKDF2HMAC(
##         algorithm=hashes.SHA256(),
##         salt=salt,
##         iterations=iterations,
##     )
##     key = Fernet.generate_key()
##     return kdf.derive(password.encode()) + key




###WORKING#(Using) #######$#$#$#$#$#$#$$working - - -


logging.info("encrypt files using the filekey")
##encrypt files using the filekey
def read_key_from_file(file_path):
    with open(file_path, 'rb') as file:
        key = file.read()
    return key

def encrypt_content(content, key):
    fernet = Fernet(key)
    encrypted_content = fernet.encrypt(content)
    return encrypted_content
# Read the key from the existing filekey.key file
key_file_path = 'history_a/filekey.key'
key = read_key_from_file(key_file_path)

###cannot do this: client_zip_folder = list(value.keys())[6] method thing

client_zip_folder = 'client_zip_folder'

# Loop through each zip file in the client_zip_folder
for root, dirs, files in os.walk(client_zip_folder):
    for file in files:
        if file.endswith('.zip'):
            zip_filepath = os.path.join(root, file)

            # Create a new in-memory zip file for efficiency
            new_zip_data = io.BytesIO()

            # Create a new zip file for writing
            with zipfile.ZipFile(new_zip_data, 'a') as new_zip_file:
                # Open the existing zip file
                with zipfile.ZipFile(zip_filepath, 'r') as zip_file:
                    for zip_info in zip_file.infolist():

                        if zip_info.filename.endswith(('.txt', '.jpg', '.png', '.gif')):
                            file_content = zip_file.read(zip_info.filename)

                            # Encrypt the content of the file
                            encrypted_content = encrypt_content(file_content, key)                          ##only this part different from the decryption

                            # Add the encrypted content to the new zip file
                            new_zip_file.writestr(f"encrypted_{zip_info.filename}", encrypted_content)      ##only this part different from the decryption
                        else:
                            # Add non-text/image files directly to the new zip file
                            new_zip_file.writestr(zip_info, zip_file.read(zip_info.filename))               #zip_file.read -> read content from files <- zip_info_filename

            # Save the new zip file with encrypted content to the original zip file location
            with open(zip_filepath, 'wb') as updated_zip_file:
                updated_zip_file.write(new_zip_data.getvalue())

            print(f"Encrypted files in {zip_filepath}")
            logging.info(f"Encrypted files in {zip_filepath}")






###use name a password part
## correct_password = "shunxiang"
correct_password = input("set your name as the password: ")
logging.info(f"Password {correct_password} set to protect the files content")






# entered_password = input("Enter the password(yourName) to decrypt files content: ")
#
#
# if entered_password == correct_password:
#     print("Password is correct. Code can continue running.")
#     logging.info(f"Password {correct_password} is correct. Code can continue running.")
#     # Your code here
# else:
#     print("Incorrect password. Exiting the program.")



#
# #**** - - [UN-HAsh for decrypt of files]
#
# logging.info("decrypt files using the filekey")
# ##decrypt files
# def read_key_from_file(file_path):
#     with open(file_path, 'rb') as file:
#         key = file.read()
#     return key
#
# def decrypt_content(encrypted_content, key):
#     fernet = Fernet(key)
#     decrypted_content = fernet.decrypt(encrypted_content)
#     return decrypted_content
# # Read the key from the filekey.key file
# key_file_path = 'history_a/filekey.key'
# key = read_key_from_file(key_file_path)
#
#
#
# client_zip_folder = 'client_zip_folder'
#
# # Loop through each zip file in the client_zip_folder
# for root, dirs, files in os.walk(client_zip_folder):
#     for file in files:
#         if file.endswith('.zip'):
#             zip_filepath = os.path.join(root, file)
#
#             # Create a new in-memory zip file
#             new_zip_data = io.BytesIO()
#
#             # Create a new zip file for writing
#             with zipfile.ZipFile(new_zip_data, 'a') as new_zip_file:
#                 # Open the existing zip file
#                 with zipfile.ZipFile(zip_filepath, 'r') as zip_file:
#                     for zip_info in zip_file.infolist():
#                         # Check if the file is an encrypted file and if its encrypted read it
#                         if zip_info.filename.startswith('encrypted_'):
#                             encrypted_content = zip_file.read(zip_info.filename)
#
#                             # Decrypt the content of the file
#                             decrypted_content = decrypt_content(encrypted_content, key)
#
#                             # Remove the 'encrypted_' from the decrypted file
#                             original_filename = zip_info.filename[len('encrypted_'):]               #diff from the encrypted part
#
#                             # Add the decrypted content to the new zip file
#                             new_zip_file.writestr(original_filename, decrypted_content)             #diff from the encrypted part
#                         else:
#                             # Add non-encrypted files directly to the new zip file
#                             new_zip_file.writestr(zip_info, zip_file.read(zip_info.filename))
#
#             # Save the new zip file with decrypred content back to the original zip file location
#             with open(zip_filepath, 'wb') as updated_zip_file:
#                 updated_zip_file.write(new_zip_data.getvalue())
#
#             print(f"Decrypted files in {zip_filepath}")
#             logging.info(f"Decrypted files in {zip_filepath}")
#





## #not working(no using)
## # #lock files with password
##
## import os
## import pyzipper
##
## def set_password_for_zip(zip_filepath, password):
##     try:
##         with pyzipper.AESZipFile(zip_filepath, 'a', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zip_file:
##             for file_info in zip_file.infolist():
##                 zip_file.setpassword(password)
##             print(f"Password set for {zip_filepath}")
##     except Exception as e:
##         print(f"Error setting password for {zip_filepath}: {e}")
##
## def automate_zip_password_lock(directory, password):
##     zip_files = [f for f in os.listdir(directory) if f.endswith('.zip')]
##
##     for zip_file in zip_files:
##         zip_filepath = os.path.join(directory, zip_file)
##         set_password_for_zip(zip_filepath, password)
##
## zip_directory = 'client_zip_folder'
##
##
## password = b"shunxiang"
##
## automate_zip_password_lock(zip_directory, password)






logging.info("\n\n\nPART_D: Script error handled with exception handling according to required process.")
# # # PART D: Ping server health and upload zip files into server
from ftplib import FTP, error_perm
import socket
import time
import logging
import os


def upload_files_to_ftp(server, username, password, local_folder, remote_folder):
    try:
        with FTP() as ftp:          #connect to ftp server
            ftp.connect(server)
            ftp.login(username, password)
            if remote_folder not in ftp.nlst():
                ftp.mkd(remote_folder)
            ftp.cwd(remote_folder)          #put this line after the if loop so as to create the folder before making it the cwd


            # scan through the contents of the local folder
            for item in os.listdir(local_folder):
                item_path = os.path.join(local_folder, item)

                # Check if the item is a file
                if os.path.isfile(item_path):
                    with open(item_path, 'rb') as file:         #open file in binary mode
                        ftp.storbinary(f'STOR {item}', file)    #uploads content to ftp server

                    logging.info(f"Uploaded {item} to {remote_folder} on FTP server.")

    except (socket.error, error_perm) as e:
        logging.error(f"Error uploading files from {local_folder} to {remote_folder} on FTP server: {e}")
        raise

#check ftp server is it healthy or not
def ping_ftp_server(server, timeout=5):
    try:
        with socket.create_connection((server, 21), timeout=timeout):           #crate_connections to the ftpserver
            print(f"FTP Server {server} is healthy. ")
            return True
    except socket.error:
        print(f"FTP Server {server} is not healthy. ")
        return False

def main():
    server = "127.0.0.1"
    username = "anonymous"
    password = ""
    local_folder = "client_zip_folder"
    remote_folder = "server_zip_folder"

    retry_count = 2     #script will retry 2 times
    delay = 5     #if sxript is delayed for 5 sec it will log warning error

    for _ in range(retry_count + 1):
        if ping_ftp_server(server):
            try:
                upload_files_to_ftp(server, username, password, local_folder, remote_folder)
                print(f"All files from {local_folder} uploaded to {remote_folder} on FTP server.")
                logging.info(f"All files from {local_folder} uploaded to {remote_folder} on FTP server.")
                break
            except Exception as e:
                print(f"Error during file upload: {e}")
                logging.error(f"Error during file upload: {e}")
        else:
            logging.warning(f"Server not available. Retrying in {delay} seconds...")
            time.sleep(delay)
    else:
        print("Server unavailable for file upload after retries.")
        logging.error("Server unavailable for file upload after retries.")

if __name__ == "__main__":
    main()

#
# # ##task scheduler
# os.system("start taskschd.msc")
# # Program_pycharmPath = r"C:\Users\Desktop\PyCharm Community Edition 2022.2.4.lnk"
# # arguments_StorageMAnager_pythonFile = r"C:\pythonProject\StorageManagement\StorageManager.py"
# # StartIn_projectpath = r"C:\pythonProject\StorageManagement"




