import socket, sys, threading
import select
import gnupg

PORT = 9876
key_home = './client_key'
gpg = gnupg.GPG(gnupghome=key_home)
server_key_id = 'D9E486E73CC89E20'

class ChatClient(threading.Thread):

    def __init__(self, port, host='localhost'):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Create public/private key if doesn't exist
        if not gpg.list_keys():
            self.key_name = input("Name: ")
            self.key_email = input("Email: ")
            rsa_default = 'RSA'
            key_type = '2048'
            key_information = gpg.gen_key_input(name_real=self.key_name, name_email=self.key_email, key_type=rsa_default, key_length=key_type)
            gpg.gen_key(key_information)
            keyids = gpg.list_keys()[0]['keyid']
            ascii_armored_public_keys = gpg.export_keys(keyids)
            print(ascii_armored_public_keys)
            result = gpg.recv_keys("pgp.key-server.io", server_key_id)
            #print(result.results)
        self.socket.connect((self.host, port))

    def send_message(self, msg):
        # Encrypt chat messages in this method
        data = bytes(msg, 'utf-8')
        self.socket.send(data)

    def ReceiveMessage(self):
        # Decrypt chat messages in this method
        while(True):
            data = self.socket.recv(1024)
            if data:
                msg = data.decode('utf-8')
                print(msg)

    def run(self):
        #print(gpg.list_keys())
        print("Starting Client")
    
        # Currently only sends the username
        self.username = input("Username: ")
        self.keyid = gpg.list_keys()[0]['keyid']
        mesg = self.username + ":" + self.keyid
        msgE = gpg.encrypt(mesg, server_key_id, always_trust=True)
        if (msgE.ok):
            #print(msgE.data.decode('utf-8'))
            data = msgE.data
            self.socket.send(data)

        # Need to get session passphrase
        
        # Starts thread to listen for data
        threading.Thread(target=self.ReceiveMessage).start()
        
        while(True):
            msg = input()
            self.send_message(msg)
        
if __name__ == '__main__':
    client = ChatClient(PORT)
    client.start() # This start run()
