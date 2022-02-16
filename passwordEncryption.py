from cryptography.fernet import Fernet

class EncryptDecrypt():

    #generate key and save it in a file
    def generate_key(self):
        if not (self.checkKeyExist()):
            key  = Fernet.generate_key()
            with open("secret.key", "wb") as key_file:
                key_file.write(key)

    #load generated key
    def load_key(self):
        return (open("secret.key", "rb").read())

    #checks if key exists
    def checkKeyExist(self):
        try:
            if(open("secret.key", "rb").read()):
                return True
        except:
            return False

    #encrypting the message
    def encrypt_password(self, message):
        key = self.load_key()
        encodedMessage = message.encode()
        f = Fernet(key) #initialise the fernet class
        encryptedMessage = f.encrypt(encodedMessage)
        return encryptedMessage

    #decrypting the message
    def decrypt_password(self, message):
        key = self.load_key()
        f = Fernet(key)
        decryptedMessage = f.decrypt(message)
        return str(decryptedMessage)