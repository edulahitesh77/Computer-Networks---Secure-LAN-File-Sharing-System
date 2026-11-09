SECURE LAN FILE SHARING - SETUP
===============================

Requirements
  Python 3 and the "cryptography" package:  pip install cryptography

Server machine
  1. Run:  python server.py
     The first run creates encryption.key (keep it on the server only).
  2. Keep server.crt and server.key in the server folder.

Client machine
  1. Copy server.crt from the server folder into the client folder.
     The client refuses to connect to any server presenting a different certificate.
  2. Run:  python client.py   and enter the server's LAN IP.

Default accounts (change these before real use)
  admin / admin123        hitesh / 1234        rahul / 1234

Regenerating the certificate
  Run generate_cert.py on the server, then copy the new server.crt to every client.
