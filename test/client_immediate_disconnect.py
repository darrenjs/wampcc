#!/usr/bin/env python

#
# Copyright (c) 2017 Darren Smith
#
# wampcc is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

import socket


host = socket.gethostname() # Get local machine name
port = 55555                # Reserve a port for your service.



s = socket.socket()
s.connect((host, port))
s.send("x")
s.close

