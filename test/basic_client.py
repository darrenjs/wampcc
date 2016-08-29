#!/usr/bin/env python

import base64
import ctypes
import hashlib
import hmac
import json
import socket
import struct
import time
import pprint as pp
import wamplite

def onWampChallenge(msg):

    serverchallenge=msg[u'challenge'].encode('utf8');
    secret="secret2"
    digest = hmac.new(secret,msg=serverchallenge , digestmod=hashlib.sha256).digest()
    signature = base64.b64encode(digest)             # note, in p3k mode, need to use the .decode() method
    signature=unicode( signature, 'utf8' );
    wamp_auth=json.dumps([5, signature, {}])
    return wamp_auth

class session_states:
    init = 0
    hello_sent = 1
    open = 2

def recv_json(sock):
    buf = bytearray(' '*20480)
    nread = sock.recv_into(buf)
    if (nread==0):
        print "remote closed socket"
        exit(1)

    packedlen = struct.unpack("!I",buf[:4])[0]
    rawstr = buf[4:4+packedlen].decode('utf-8')
    jsonmsg = json.loads(rawstr)
    print "recv:", jsonmsg
    return jsonmsg

def send_json(sock, msg):
    packed_len = struct.pack("!I", len(msg))
    sock.send(packed_len)
    sock.send(msg)

session_state=session_states.init

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
host = socket.gethostname() # Get local machine name
port = 55555                # Reserve a port for your service.


print "connecting ..."
s.connect((host, port))
wamplite.rawsocket_handshake( s );


# start handshakre
print "sending hello ..."
wamp_hello = json.dumps([1, "default_realm", {"authid": "peter", "authmethods": ["wampcra"], "roles": {}}] )
send_json(s, wamp_hello);

# receive CRA challenge
jsonmsg = recv_json(s)

# Send abort
#print "sending abort ..."
#wamp_abort =  json.dumps( [3, {}, "error.abort"] )
#send_json(s, wamp_abort)


# Send authentication
print "sending auth ..."
wamp_auth = onWampChallenge(jsonmsg[2] )
send_json(s, wamp_auth)

# Accept welcome message
jsonmsg = recv_json(s)


# Send subscribption
print "sending subscribe ..."
wamp_subscribe =  json.dumps( [32, 1, {}, "USERHB"] )
send_json(s, wamp_subscribe)




if (jsonmsg[0]==2):
    session_state=session_states.open
    print "wamp session open, session id:" , jsonmsg[1]

while (session_state==session_states.open):
    jsonmsg = recv_json(s)

s.close
