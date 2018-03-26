import socket, ssl
import re
import subprocess
import argparse
import select
import time

from ssl_packet import SSLPacket, SSLHandshakeClientHelloRecord, SSLExtensionServerName


def init_ssl_ca():
    subprocess.call(['openssl', 'genrsa', '-out', 'myCA.key', '2048'])
    subprocess.call(['openssl', 'req', '-x509', '-new', '-nodes', '-key', 'myCA.key',
                     '-sha256', '-days', '1825', '-out', 'myCA.pem', '-subj',
                     '/C=NL/ST=ZuidHolland/L=Rotterdam/O=SecOps/OU=ITDep/CN=SecOps'])


def generate_ssl(host):
    subprocess.call(['rm', './demoCA/index.txt'])
    subprocess.call(['touch', './demoCA/index.txt'])
    subprocess.call(['mkdir', '-p', './certs'])

    subprocess.call(['openssl', 'genrsa', '-out', './certs/{}.key'.format(host), '2048'], stderr=subprocess.DEVNULL)
    subprocess.call(['openssl', 'req', '-new', '-key', './certs/{}.key'.format(host), '-out',
                     './certs/{}.csr'.format(host), '-subj',
                     '/C=NL/ST=ZuidHolland/L=Rotterdam/O=SecOps/OU=ITDep/CN={}'.format(host)],
                    stderr=subprocess.DEVNULL)
    subprocess.call(['openssl', 'ca', '-batch', '-out', './certs/{}.crt'.format(host), '-startdate', '20160107071311Z',
                     '-enddate', '20190107071311Z', '-cert', 'myCA.pem', '-keyfile', 'myCA.key', '-infiles',
                     './certs/{}.csr'.format(host)], stderr=subprocess.DEVNULL)

    return './certs/{}.crt'.format(host), './certs/{}.key'.format(host)


def get_host(pkt):
    try:
        record = list(filter(lambda e: isinstance(e, SSLHandshakeClientHelloRecord), pkt.records))[0]
    except IndexError:
        return None

    for ext in record.extensions:
        if isinstance(ext.data, SSLExtensionServerName):
            host = ext.data.name
            print('Found host in client hello: {}'.format(host))
            return host
    return None


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
        sock_ips_client.listen(3)

        while True:
            try:
                print('-' * 20)
                conn_ips_client, client_address = sock_ips_client.accept()

                init_pkt = conn_ips_client.recv(4096, socket.MSG_PEEK)
                init_pkt = SSLPacket.from_pkt(init_pkt)

                host = get_host(init_pkt)
                if not host:
                    continue

                crt, key = generate_ssl(host)

                try:
                    conn_ssl_ips_client = ssl.wrap_socket(conn_ips_client, server_side=True, certfile=crt, keyfile=key)
                    conn_ssl_ips_client.setblocking(1)
                except (ssl.SSLError, OSError) as e:
                    print('Could not wrap client - ips socket: {}'.format(e))
                    continue

                try:
                    conn_ssl_ips_client.do_handshake()
                    conn_ssl_ips_client.setblocking(0)
                except (ssl.SSLError, OSError) as e:
                    print('Could not do SSL handshake: {}'.format(e))
                    break

                sock_ips_world = socket.socket()
                sock_ips_world = ssl.wrap_socket(sock_ips_world)

                try:
                    sock_ips_world.connect((host, 443))
                    sock_ips_world.setblocking(1)
                    sock_ips_world.settimeout(3)
                except ssl.SSLWantReadError as e:
                    print('Could not connect remote server: {}'.format(e))
                    break

                while True:
                    try:
                        data_client = conn_ssl_ips_client.recv(4096)
                    except ssl.SSLError as e:
                        print('Could not read from client: {}'.format(e))
                        break

                    if not data_client:
                        break

                    sock_ips_world.sendall(data_client)

                    while True:
                        try:
                            data_world = sock_ips_world.recv(4096)
                        except (ssl.SSLWantReadError, socket.timeout) as e:
                            print('Could not read from www: {}'.format(e))
                            break

                        try:
                            conn_ssl_ips_client.sendall(data_world)
                        except ssl.SSLWantWriteError as e:
                            print('Error sending to client: {}'.format(e))

                        if not data_world:
                            break

                print('Closing')
                sock_ips_world.close()
                conn_ssl_ips_client.close()

            except KeyboardInterrupt:
                sock_ips_client.close()
                print("\nTerminating...")
                break
