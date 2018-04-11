from signal import *

import base64
import binascii
import ctypes
import hashlib
import socket
import struct
import sys
import traceback

c_uint8 = ctypes.c_uint8
c_uint16 = ctypes.c_uint16
c_uint32 = ctypes.c_uint32
c_uint64 = ctypes.c_uint64

port = int(sys.argv[1])
conn = 0

OPEN_WEBSOCKET_PREFIX = 'GET / HTTP/1.1'

class WebSocketFrame(ctypes.BigEndianStructure):
    _fields_ = [
        ("fin", c_uint8, 1),
        ("rsv1", c_uint8, 1),
        ("rsv2", c_uint8, 1),
        ("rsv3", c_uint8, 1),
        ("opcode", c_uint8, 4),
        ("mask", c_uint8, 1),
        ("payloadLen", c_uint8, 7),
    ]
    payloadLen = 0
    maskingKey = ''
    payload = ''

    def setRawData(self, rawData):
        ctypes.memmove(ctypes.addressof(self), rawData, ctypes.sizeof(self))
        # TODO: Handle all payload sizes
        fieldStart = 2
        if self.mask:
            self.maskingKey = rawData[fieldStart:fieldStart+4]
            fieldStart += 4

        self.payload = rawData[fieldStart:]

    def unmaskPayloadData(self):
        unmaskedPayload = ''
        for i in range(0, self.payloadLen):
            unmaskedPayload += chr(ord(self.payload[i]) ^ ord(self.maskingKey[i%4]))

        return unmaskedPayload


def binPrint(data):
    for d in bytearray(data):
        print "{0:b}".format(d)

def clean(*args):
    global conn
    conn.close()
    websock.close()
    print("Cleaned up socket")
    sys.exit(0)

def openSock():
    websock = socket.socket()
    websock.bind(('', port))
    websock.listen(1)
    return websock

KEY_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
def calculatResponseKey(requestKey):
    responseKey = base64.b64encode(hashlib.sha1(requestKey + KEY_MAGIC).digest())
    print "Response key:", responseKey
    return responseKey

WEBSOCKET_KEY_PREFIX = 'Sec-WebSocket-Key: '
WEBSOCKET_RESPONSE_PREFIX = 'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '
def responseForOpenWebSocket(request):
    for line in request.split('\r\n'):
        if not line.startswith(WEBSOCKET_KEY_PREFIX):
            continue
        key = line.split(WEBSOCKET_KEY_PREFIX)[1]
        print "Got key", key
        responseKey = calculatResponseKey(key)
        return WEBSOCKET_RESPONSE_PREFIX + responseKey + '\r\n\r\n'

def responseForFrame(frame):
    binPrint(frame)
    test = WebSocketFrame()

    test.setRawData(frame)
    print
    print ctypes.sizeof(test)
    print test.fin
    print test.rsv1
    print test.rsv2
    print test.rsv3
    print test.opcode
    print test.mask
    print test.payloadLen
    binPrint(test.maskingKey)
    test.unmaskPayloadData()

def listen(sock):
    global conn
    print 'Listening on port', port
    conn, addr = sock.accept()
    print 'Received connection from ' + addr[0]
    try:
        while 1:
            data = conn.recv(1024)
            if data == "":
                print "Connection closed?"
                return

            print "Received data:"
            print data

            response = ""
            if data.startswith(OPEN_WEBSOCKET_PREFIX):
                print "Opening WebSocket"
                response = responseForOpenWebSocket(data)
                conn.sendall(response)
            else:
                response = responseForFrame(data)

    except RuntimeError as e:
        print "Error:", e
        print "Closed connection"
        conn.close()

for sig in (SIGABRT, SIGILL, SIGINT, SIGSEGV, SIGTERM):
    signal(sig, clean)

websock = openSock()

while 1:
    try:
        listen(websock)
    except:
        traceback.print_exc()
        clean()
