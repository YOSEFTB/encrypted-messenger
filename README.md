# encrypted-messenger 
This project implements a CLI messaging service, with the client side in C++ and the server side in Python. Users can sign up with a unique username and send encrypted messages (text, files, images, etc.) to other users. Messages are encrypted using AES, with keys exchanged via RSA.
 
Users can pull their messages from the server at any time. The service supports concurrency via Python threads and handles multiple clients, including invalid requests gracefully.
 
Communication takes place over TCP using a custom binary protocol composed of fields, opcodes, and payloads. Boost.Asio is used on the client side; Python sockets are used on the server.
 
The system enforces logical constraints (e.g., disallowing message sending before key exchange or client list retrieval). At logout, user info is saved locally to allow automatic login later.

Designed as a practical exploration of networking, encryption, and low-level protocol design.

