import socket, sys, threading
import gnupg
# Simple chat client that allows multiple connections via threads

PORT = 9876 # the port number to run our server on
key_home = './server_key/'
gpg = gnupg.GPG(gnupghome=key_home)

class ChatServer(threading.Thread):
    
    def __init__(self, port, host='localhost'):
        threading.Thread.__init__(self)
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
        self.port = port
        self.host = host
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = {} # current connections
        self.passphrase = input("Passphrase: ")
        self.client_key_ids = []
        
        try:
            self.server.bind((self.host, self.port))
        except socket.error:
            print('Bind failed %s' % (socket.error))
            sys.exit()

        self.server.listen(10)
        
    # Not currently used. Ensure sockets are closed on disconnect
    def exit(self):
        self.server.close()

    # Broadcast chat message to all connected clients
    def broadcast (self, username, msg):
        for user in self.connections:
            if (user is not username):
                try:
                    msgE = gpg.encrypt(username+": "+msg, recipients=[], symmetric="AES256", passphrase=self.passphrase)
                    if (msgE.ok):
                        data = msgE.data
                        self.connections[user].send(data)
                except:
                    # broken socket connection
                    conn.close()
                    # broken socket, remove it
                    if conn in self.connections:
                        self.connections.remove(conn)

    # Continually listens for messages and broadcasts the messages
    # to all connected users.
    def run_thread(self, username, conn, addr):
        print('Client connected with ' + addr[0] + ':' + str(addr[1]))
        while True:
            try:
                data = conn.recv(1024)
                mesg = data.decode('utf-8')
                msgD = gpg.decrypt(mesg, passphrase=self.passphrase)
                self.broadcast(username, msgD.data.decode('utf-8'))
                print(username + ": " + msgD.data.decode('utf-8')) 
            except:
                self.broadcast(username, username+"(%s, %s) is offline\n" % addr)
                conn.close() # Close
                del self.connections[username]
                return

    # Start point of server
    def run(self):
        print('Waiting for connections on port %s' % (self.port))
        # We need to run a loop and create a new thread for each connection
        while True:
            conn, addr = self.server.accept()

            # First message after connection is username
            data = conn.recv(1024)
            mesg = data.decode('utf-8')
            msgD = gpg.decrypt(mesg)
            if (msgD.ok):
                msg = msgD.data.decode('utf-8')
                username = msg.split(":")[0]
                keyid = msg.split(":")[1]
                if keyid not in self.client_key_ids:
                    result = gpg.recv_keys("pgp.key-server.io", keyid)
                if (username not in self.connections):
                    self.connections[username] = conn
                    print(username, "connected")
                    # Need to send the encrypted session passphrase based on the keyid sent with username
                    passE = gpg.encrypt(self.passphrase, keyid, always_trust=True)
                    if (passE.ok):
                        data = passE.data
                        conn.send(data)
                    threading.Thread(target=self.run_thread, args=(username, conn, addr)).start()
                else:
                    conn.send(bytes(username+" already exists.  Please restart client.",'utf-8'))
                    conn.close()

if __name__ == '__main__':
    server = ChatServer(PORT)
    # Run the chat server listening on PORT
    server.run()
