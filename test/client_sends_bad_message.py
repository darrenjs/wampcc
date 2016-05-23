#!/usr/bin/env python

import socket
import time

s = socket.socket()         # Create a socket object
host = socket.gethostname() # Get local machine name
port = 55555                # Reserve a port for your service.

s.connect((host, port))

# print "connecting ... not doing anything"

# while True:
#     time.sleep(60)  # sleep 1 minute

# print s.recv(1024)
# s.close


s.send("hello")



while True:
    time.sleep(60)  # sleep 1

s.close
