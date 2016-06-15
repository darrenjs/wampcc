#!/usr/bin/env python

import socket


host = socket.gethostname() # Get local machine name
port = 55555                # Reserve a port for your service.



s = socket.socket()
s.connect((host, port))
s.send("x")
s.close

