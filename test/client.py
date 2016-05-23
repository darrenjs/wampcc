#!/usr/bin/env python

import socket
import time
import json
import struct


def send_json(sock, msg):
    packed_len = struct.pack("!I", len(msg))
    sock.send(packed_len)
    sock.send(msg)


s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
host = socket.gethostname() # Get local machine name
port = 55555                # Reserve a port for your service.


s.connect((host, port))


wamp_hello = json.dumps([1, "default_realm", {"authid": "peter", "authmethods": ["wampcra"], "roles": {}}] )

send_json(s, wamp_hello);

# print "connecting ... not doing anything"

# while True:
#     time.sleep(60)  # sleep 1 minute

# print s.recv(1024)
# s.close

recv_msg = s.recv(2048)
print "recv: " + recv_msg


# wamp_subscribe=json.dumps([32, 1, {}, "xxx"])
# send_json(s, wamp_subscribe);

# wamp_authenticate=json.dumps([5, "8BZkFPz2yVGRvCqK7EKK6NLhVnDiqXr4+0+32QX0gzc=", {}])
# send_json(s, wamp_authenticate);


while True:
    recv_msg = s.recv(2048)
    if not recv_msg:
        print "closed by peer"
        break
    print "recv: " + recv_msg

s.close
