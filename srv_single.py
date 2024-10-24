#!/usr/bin/env python3
# Foundations of Python Network Programming, Third Edition
# https://github.com/brandon-rhodes/fopnp/blob/m/py3/chapter07/srv_single.py
# Single-threaded server that serves one client at a time; others must wait.
# use of this server is python3 ./srv_single.py ''

import argparse
import ssl
import zen_utils

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Example client')
    parser.add_argument('host', help='IP or hostname')
    #parser.add_argument('cafile', help='Path to a CA certificate file.')
    #parser.add_argument('certfile', help='Path to a certificate/key pem file.')
    parser.add_argument('-e', action='store_true', help='cause an error')
    parser.add_argument('-p', metavar='port', type=int, default=1060,
                        help='TCP port (default 1060)')
    args = parser.parse_args()
    address = (args.host, args.p)
   # address = zen_utils.parse_command_line('simple single-threaded server')
    listener = zen_utils.create_srv_socket(address)
    purpose = ssl.Purpose.CLIENT_AUTH
    
    context = ssl.create_default_context(purpose, cafile="./keys/backend.crt")
    context.load_verify_locations(capath='./keys/')
    context.verify_mode = ssl.CERT_NONE             
    context.check_hostname = False
    context.load_cert_chain("./keys/backend.pem")
    zen_utils.accept_connections_forever(listener, context)
