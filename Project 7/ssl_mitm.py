import socket, ssl
import re
import subprocess
import argparse


from ssl_packet import SSLPacket, SSLHandshakeClientHelloRecord, SSLExtensionServerName


def init_ssl_ca():
    subprocess.call(['openssl', 'genrsa', '-out', 'myCA.key', '2048'])
    subprocess.call(['openssl', 'req', '-x509', '-new', '-nodes', '-key', 'myCA.key',
                     '-sha256', '-days', '1825', '-out', 'myCA.pem', '-subj',
                     '/C=NL/ST=ZuidHolland/L=Rotterdam/O=SecOps/OU=ITDep/CN=SecOps'])


def generate_ssl(host):
    subprocess.call(['openssl', 'genrsa', '-out', '{}.key'.format(host), '2048', '-subj',
                     '"/C=NL/ST=Zuid Holland/L=Rotterdam/O=Sparkling Network/OU=IT Department/CN={}"'.format(host)])
    subprocess.call(['openssl', 'req', '-new', '-key', '{}.key'.format(host), '-out', '{}.csr'.format(host)])
    subprocess.call(['openssl', 'x509', '-req', '-in', '{}.csr'.format(host), '-CA', 'myCA.pem', '-CAkey', 'myCA.key',
                     '-CAcreateserial', '-out {}.crt'.format(host), '-days', '1825', '-sha256'])

    return '.crt'.format(host), '{}.key'.format(host)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--init-ca', dest='init_ssl_ca', action='store_true',
                        help='Initialize a CA')

    args = parser.parse_args()

    if args.init_ssl_ca:
        init_ssl_ca()
    else:
        listening_port = 8443

        print('Started listening on {}'.format(listening_port))

        sock_ips_client = socket.socket()
        sock_ips_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_ips_client.bind(('0.0.0.0', listening_port))
        sock_ips_client.listen(5)

        while True:
            try:
                connection, client_address = sock_ips_client.accept()

                print(sock_ips_client.getsockname())

                init_pkt = connection.recv(4096, socket.MSG_PEEK)
                init_pkt = SSLPacket.from_pkt(init_pkt)

                host = None
                if isinstance(init_pkt, SSLHandshakeClientHelloRecord):
                    for ext in init_pkt.extensions:
                        if isinstance(ext.data, SSLExtensionServerName):
                            host = ext.data.name

                if not host:
                    continue

                crt, key = generate_ssl(host)

                connstream = ssl.wrap_socket(connection, server_side=True, certfile="yrck.nl.crt", keyfile="yrck.nl.key")
                connstream.do_handshake()
                while True:
                    data_client = connstream.recv(4096).decode()
                    print(data_client)

                    if not data_client:
                        break

                    host = re.search(r"Host: (.+)\r\n", data_client).group(1)
                    print(host)

                    sock_ips_world = socket.socket()
                    sock_ips_world = ssl.wrap_socket(sock_ips_world)
                    sock_ips_world.connect((host, 443))
                    sock_ips_world.sendall(data_client.encode())
                    data_world = sock_ips_world.recv(4096)
                    sock_ips_world.close()

                    connstream.sendall(data_world)
                    connstream.close()
                    break

            except KeyboardInterrupt:
                print("\nTerminating...")
                break
