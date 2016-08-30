

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
