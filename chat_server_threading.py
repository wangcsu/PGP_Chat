import socket, sys, threading

# Simple chat client that allows multiple connections via threads

PORT = 9876 # the port number to run our server on

class ChatServer(threading.Thread):
    
    def __init__(self, port, host='localhost'):
        threading.Thread.__init__(self)
        self.port = port
        self.host = host
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = {} # current connections
        
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
                    self.connections[user].send(bytes(user+": "+msg,'utf-8'))
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
                self.broadcast(username, data.decode('utf-8'))
                print(username + ": " + data.decode('utf-8')) 
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
            username = data.decode('utf-8')
            if (username not in self.connections):
                self.connections[username] = conn
                print(username, "connected")
                # Need to send the encrypted session passphrase based on the keyid sent with username
                threading.Thread(target=self.run_thread, args=(username, conn, addr)).start()
            else:
                conn.send(bytes(username+" already exists.  Please restart client.",'utf-8'))
                conn.close()

if __name__ == '__main__':
    server = ChatServer(PORT)
    # Run the chat server listening on PORT
    server.run()
