# encrypted-messenger 

## Overview

This project implements a CLI messaging service, with the client side in C++ and the server side in Python. Users can send messages to each other using the service.


## Features

Users can sign up with a unique username, request the list of other users, and send encrypted messages (text, files, images, etc.) to other users. Users can pull their messages from the server at any time. The service supports concurrency via Python threads and handles multiple clients, and catches invalid requests gracefully.
The system enforces logical constraints (e.g., disallowing message sending before key exchange or client list retrieval). At logout, user info is saved locally to allow automatic login later.


## Communication and protocol

Communication takes place over TCP using a custom binary protocol composed of fields, opcodes, and payloads. Boost.Asio is used on the client side; Python sockets are used on the server.


## Encryption

Encryption is implemented using a combination of RSA and AES. Users exchange symmetric AES keys that are encrypted using RSA, and they communicate using that key for encryption. Actual encrytion is handled by the system. The system blocks message sending if no keys have been exchanged. See documentation about RSA and AES for more details about the role of public/private keys, and symmetric keys.


Designed as a practical exploration of networking, encryption, and low-level protocol design.

