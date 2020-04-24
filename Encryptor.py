import sys, argparse, os
from cryptography.hazmat.primitives import hashes, serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend as crypto_default_backend 
from cryptography.fernet import Fernet
from os import path 
#Classes
class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)
#Encryption Methods
def rsaEncrypt(inputfile, outputfile, remove):
    if(outputfile == ''):  outputfile = inputfile
    if(not os.path.isfile(inputfile)):#input is a dir
        if(os.path.isfile(outputfile)):#output is a file
            print('Output Directory is a file, expected directory')
        else: 
            print('encrypting ', input)
    private_key = generate_privatekey()
    with open(inputfile, 'rb') as plain:
        data = plain.read()
        public_key = private_key.public_key()
        encoded = public_key.encrypt(
        data,
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
                )
        )
        if(inputfile == outputfile):
            if(remove): 
                with open(inputfile, 'wb') as plain: plain.write(encoded)
                return True
            else: 
                with open(outputfile+'.enc', 'wb') as file: file.write(encoded)

def encryptFile(input, output, f, remove):
    with open(input, "rb") as file:  file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    if(input == output): 
        if(remove): 
            with open(output , "wb") as file: file.write(encrypted_data)
            return True
        else: 
            with open(output + '.enc', "wb") as file: file.write(encrypted_data)
    else: 
        with open(output , "wb") as file: file.write(encrypted_data)
def encrypt(input, output, remove):
    if(output == None or output == ''): 
        output = input
    if(not os.path.isfile(input)):#input is a dir
        if(os.path.isfile(output)):#output is a file
            print('Output Directory is a file, expected directory')
        else: 
            print('encrypting ', input)
    key = Fernet.generate_key()
    f = Fernet(key)
    encryptFile(input, output, f, remove)
    with open("sym.key", "wb") as key_file:
        key_file.write(key)
#Decryption Methods
def DecryptFile(input, output, f):
    with open(input, 'rb') as file: file_data = file.read()
    try:
        decrypted_data = f.decrypt(file_data)
    except: 
        print('Key does not match encrypted file')
        sys.exit(1)
    if(input== output):
        if(remove): 
            with open(output, 'wb') as file: file.write(decrypted_data)
            return True
        else:
            with open(output + '.dec', 'wb') as file: file.write(decrypted_data)
def decrypt(input, output, key, remove):
    if(input.endswith('.enc') and output == ''): output = input[:-4]
    elif(output == ''): output = input
    try: plainkey = open(key, "rb").read()
    except:
        print('Decryption key not found')
        sys.exit()
    try:
        f = Fernet(plainkey)
        return DecryptFile(input, output,f)
    except:
        return rsaDecrypt(input, output, key, remove)
    
def rsaDecrypt(input, output, key, remove):
    with open(key, "rb") as key_file: #loadkey
     try:   
        private_key = crypto_serialization.load_pem_private_key(
         key_file.read(),
         password=None,
         backend=crypto_default_backend()
        )
        return rsaDecryptFile(input,output, private_key, remove)
     except Exception as e:
        print(e) 
        print("Input file isn't RSA encrypted")
        sys.exit(1)
def rsaDecryptFile(input, output, key, remove): 
    print(key)    
    with open(input, 'rb') as file:
        try:
            encrypted_data = file.read()
            unencrypted_data = key.decrypt(
            encrypted_data,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
                )
            )
        except Exception as e:
           print(e)
           sys.exit(1)
    if(input == output):
        if(remove):
            with open(output, 'wb') as out: out.write(unencrypted_data)
            return True
        else: 
            with open(output+'dec', 'wb') as out: out.write(unencrypted_data)
#Other Methods
def ConflictCheck(args, argv):
    if(not os.path.isfile(args.inputfile)):
        print(args.inputfile, ' does not exist!')
        sys.exit()
    elif(argv[0] == args.inputfile ):
        print('Please use a different input file')
        sys.exit(1)
    elif(argv[0] == args.o):
        print('Please use a different output file')
        sys.exit(1)
    elif(args.symmetric and args.asymmetric):
        print('Please use only one encryption method')
        sys.exit(1)
    elif(args.d is not None and args.symmetric is True): 
        print('-s and -d  can\'t be used together')
        sys.exit(1)
    return True
def generate_privatekey():
    key = rsa.generate_private_key(
    backend=crypto_default_backend(),
    public_exponent=65537,
    key_size=2048
    )
    private_key = key.private_bytes(
    crypto_serialization.Encoding.PEM,
    crypto_serialization.PrivateFormat.PKCS8,
    crypto_serialization.NoEncryption())
    open('private.key', 'w')
    with open('private.key', 'wb') as privatefile:
        privatefile.write(private_key) 
    return key
#Main
def main(argv):
    parser = MyParser()
    optional = parser._action_groups.pop() 
    required = parser.add_argument_group('required arguments')
    required.add_argument('inputfile', help='The file you want to encrypt. Entering a directory will encrypt or decrypt all the contents of the directory')
    optional.add_argument('-d', help ='Use this option to decrypt your input file', metavar = 'decryptKey')
    optional.add_argument('-s','--symmetric',help = 'Generates a key to encrypt the input', action='store_true')
    optional.add_argument('-a', '--asymmetric', help = 'Generates an rsa key pair, creates a private key file, and encrypts the input file with the public key', action = 'store_true')
    optional.add_argument('-r','--remove',help = 'Deletes your input after encryption, use with caution', action='store_true')
    optional.add_argument('-o',metavar = 'outputfile', help='The name of the outputfile, no argument renames input file', default = '')
    parser._action_groups.append(optional) 
    args = parser.parse_args()
    #Move if statements to ConflictCheck
    print(args)
    if (not len(sys.argv) > 1):
        parser.print_help(sys.stderr)
        sys.exit(1) 
    elif(not ConflictCheck(args, argv)): 
        print('Conflict!')
        sys.exit(1)
    elif(args.symmetric):
        if(not path.exists(args.o)and args.o != ''):
            open(args.o, 'w')    
        override = encrypt(args.inputfile, args.o, args.remove)
    elif(args.asymmetric):
        override = rsaEncrypt(args.inputfile, args.o, args.remove)
    elif(args.d is not None):
        if(not path.exists(args.o) and args.o != ''):
            open(args.o, 'w') 
        if(not path.exists(args.d)):
            print('Decrypt key does not exist')
            sys.exit(1)
        override = decrypt(args.inputfile, args.o, args.d, args.remove)
    if(args.symmetric == False and args.d == None and args.asymmetric == False):
        print('Please use a decryption or an encryption flag')
        sys.exit(1)
    if(args.remove and override != True): os.remove(args.inputfile)
if __name__ == '__main__':
    main(sys.argv)
