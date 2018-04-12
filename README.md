# WebSocketConsole
A basic implementation of the HTML5 WebSocket spec allowing sending and receiving messages

This script implements a barebones HTML5 WebSocket server based on [RFC 6455](https://tools.ietf.org/html/rfc6455).

## Current Features
* Accept socket connections
* Calculate socket keys
* Respond to pings
* Handle payloads <126 bytes
* Unmask messages
* Send arbitrary text messages to client

## Usage
`python websocketconsole.py <port>`

Start a listener on `<port>`. When a connection has been established, type into the console and press return to send a text frame.

## TODO
* Handle all message sizes
* Handle fragmented messages
* Properly handle all opcodes
* Allow sending messages for all opcodes
* Make console print nicer
* Better interface
