import struct
import json

class WampMsgType:
    UNDEF=0
    HELLO = 1
    WELCOME = 2
    ABORT = 3
    CHALLENGE = 4
    AUTHENTICATE = 5
    GOODBYE = 6
    HEARTBEAT = 7
    ERROR = 8
    PUBLISH = 16
    PUBLISHED = 17
    SUBSCRIBE = 32
    SUBSCRIBED = 33
    UNSUBSCRIBE = 34
    UNSUBSCRIBED = 35
    EVENT = 36
    CALL = 48
    CANCEL = 49
    RESULT = 50
    REGISTER = 64
    REGISTERED = 65
    UNREGISTER = 66
    UNREGISTERED = 67
    INVOCATION = 68
    INTERRUPT = 69
    YIELD = 70

def rawsocket_unpack(buf):
    packedlen = struct.unpack("!I",buf[:4])[0]
    rawstr = buf[4:4+packedlen].decode('utf-8')
    return json.loads(rawstr)


def rawsocket_send(sock, msg):
    packed_len = struct.pack("!I", len(msg))
    sock.send(packed_len)
    sock.send(msg)


def rawsocket_handshake_array():
    return bytearray(b'\x7F\xA1\x00\x00')


def rawsocket_handshake(sock):
    """Perform a synchronous rawsocket handshake"""

    # send handshake
    handshake = bytearray(b'\x7F\xA1\x00\x00')
    sock.send( handshake )

    # read reply
    target_nread = 4
    actual_nread = 0
    buf = bytearray( target_nread )
    while (target_nread != actual_nread):
        n = sock.recv_into(buf, target_nread-actual_nread)
        actual_nread += n


def rawsocket_ping(sock):
    ping = bytearray(b'\x01\x00\x00\x00')
    sock.send( ping )

    # read pong
    target_nread = 4
    actual_nread = 0
    buf = bytearray( target_nread )
    while (target_nread != actual_nread):
        n = sock.recv_into(buf, target_nread-actual_nread)
        actual_nread += n
