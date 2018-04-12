from signal import *

import base64
import binascii
import ctypes
import hashlib
import socket
import struct
import sys
import threading
import traceback

c_uint8 = ctypes.c_uint8
c_uint16 = ctypes.c_uint16
c_uint32 = ctypes.c_uint32
c_uint64 = ctypes.c_uint64

port = int(sys.argv[1])
conn = None
websock = None
webSockThread = None

OPEN_WEBSOCKET_PREFIX = 'GET / HTTP/1.1'

OPCODE_PING = 9

DEBUG = 1

shouldQuit = 0

class WebSockThread(threading.Thread):
    def run(self):
        global websock
        global shouldQuit
        websock = openSock()
        websock.settimeout(3)
        dprint('Listening on port', port)

        while not shouldQuit:
            try:
                listen(websock)
            except socket.timeout:
                continue
            except:
                traceback.print_exc()
                clean()


# TODO: Handle fragmented messages
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

    def getRawData(self):
        data = ctypes.string_at(ctypes.addressof(self), ctypes.sizeof(self))
        data += self.maskingKey
        data += self.payload

        return data

def dprint(*arg):
    if DEBUG:
        print arg

def dprintBin(*arg):
    if DEBUG:
        printBin(arg)

def printBin(data):
    for d in bytearray(data):
        print "{0:b}".format(d)

def clean(*args):
    global conn
    global websock
    global webSockThread
    global shouldQuit
    shouldQuit = 1
    if websock:
        websock.close()
    if conn:
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()

def openSock():
    global websock
    websock = socket.socket()
    websock.bind(('', port))
    websock.listen(1)
    return websock

KEY_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
def calculatResponseKey(requestKey):
    responseKey = base64.b64encode(hashlib.sha1(requestKey + KEY_MAGIC).digest())
    dprint ("Response key:", responseKey)
    return responseKey

WEBSOCKET_KEY_PREFIX = 'Sec-WebSocket-Key: '
WEBSOCKET_RESPONSE_PREFIX = 'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '
def responseForOpenWebSocket(request):
    for line in request.split('\r\n'):
        if not line.startswith(WEBSOCKET_KEY_PREFIX):
            continue
        key = line.split(WEBSOCKET_KEY_PREFIX)[1]
        dprint("Got key", key)
        responseKey = calculatResponseKey(key)
    return WEBSOCKET_RESPONSE_PREFIX + responseKey + '\r\n\r\n'

def pongForPing(frame):
    pong = frame
    pong.opcode = 0xA
    return pong.getRawData()

def responseForFrame(frame):
    if frame.opcode == OPCODE_PING:
        dprint("Got ping")
        return pongForPing(frame)

    frame.unmaskPayloadData()
    return None

def listen(sock):
    global conn
    global shouldQuit
    conn, addr = sock.accept()
    dprint('Received connection from ' + addr[0])
    conn.settimeout(3)
    while not shouldQuit:
        try:
            data = conn.recv(1024)
            if data == "":
                dprint("Connection closed?")
                return

            dprint("Received data:")
            dprint(data)

            response = None
            if data.startswith(OPEN_WEBSOCKET_PREFIX):
                dprint("Opening WebSocket")
                response = responseForOpenWebSocket(data)
            else:
                frame = WebSocketFrame()
                frame.setRawData(data)
                print frame.unmaskPayloadData()
                response = responseForFrame(frame)

            if response:
                conn.sendall(response)
        except socket.timeout:
            continue

def sendText(text):
    frame = WebSocketFrame()
    frame.fin = 1
    frame.rsv1 = 0
    frame.rsv2 = 0
    frame.rsv3 = 0
    frame.opcode = 1
    frame.mask = 0
    frame.payloadLen = len(text) # TODO: Exptend to work with text longer than 126
    frame.payload = text
    return frame.getRawData()

for sig in (SIGABRT, SIGILL, SIGINT, SIGSEGV, SIGTERM):
    signal(sig, clean)

webSockThread = WebSockThread()
webSockThread.start()
try:
    while (1):
        line = raw_input("console> ").strip()
        if line == "":
            continue

        lineFrame = sendText(line)
        conn.sendall(lineFrame)

except:
    traceback.print_exc()
    print("Running clean")
    webSockThread.shouldQuit = 1
    clean()
