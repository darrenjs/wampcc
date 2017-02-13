#!/usr/bin/env python

#
# Copyright (c) 2017 Darren Smith
#
# wampcc is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

##
## Basic wamp server, used for development purpose only. Not production quality.
##

import struct
import binascii
import socket
import wamplite
import json

HOST, PORT = "localhost", 55555

class session_state:
    handshaking = 1
    receiving_hello = 2
    receiving_authentication = 3
    open = 4

if __name__ == "__main__":
    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv.bind((HOST, PORT))
    serv.listen(5)
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    while True:
        print 'listening for next client on ' + HOST + ":" +  str(PORT)
        conn, addr = serv.accept()
        print 'client connected ... ', addr
        client_state = session_state.handshaking
        while True:
            buf = bytearray(' '*20480)
            nread = conn.recv_into(buf)

            if (nread==0):
                print "remote closed socket"
                break

            print "recv: " + str(nread) + ", " + binascii.hexlify(buf[:nread]);
            if (client_state == session_state.handshaking):
                handshake = wamplite.rawsocket_handshake_array()
                conn.send(handshake);
                client_state = session_state.receiving_hello
            else:
                # TODO: add segmentation handlingprint "state not handled"
                jsonmsg = wamplite.rawsocket_unpack(buf)
                print "json:", jsonmsg
                wamp_msg_type=jsonmsg[0]
                if (wamp_msg_type == wamplite.WampMsgType.SUBSCRIBE):
                    print "rejecting subscription request"
                    request_id=jsonmsg[1]
                    wamplite.rawsocket_send(conn, json.dumps([wamplite.WampMsgType.ERROR,
                                                              wamplite.WampMsgType.SUBSCRIBE,
                                                              request_id,
                                                              {},
                                                              "wamp.error.not_authorized"]))
                else:
                    if (client_state == session_state.receiving_hello) :
                        print "sending challenge"
                        msg = json.dumps([4, u'wampcra', {u'challenge': u'{"session": "1", "authid": "peter", "authmethod": "wampcra", "authprovider": "programdb", "authrole": "user", "nonce": "TlkJb<$X9U>FgOd|LyTVIBWedxL[\\\\>", "timestamp": "2017-01-22T13:00:36.407Z"}'}])
                        wamplite.rawsocket_send(conn, msg)
                        client_state = session_state.receiving_authentication
                    elif (client_state == session_state.receiving_authentication) :
                        print "sending open"
                        msg = json.dumps([2, 1, {"roles": {"broker": {}, "dealer": {}}}]);
                        wamplite.rawsocket_send(conn, msg)
                        client_state = session_state.open
                    else:
                        print "state not handled"
                        # TODO: identify a subscribe request, and reject it.

        print 'client disconnected'


