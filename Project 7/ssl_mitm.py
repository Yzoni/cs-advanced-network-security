import socket
import ssl
import subprocess
import argparse
import logging as logging
import sys
import threading

from ssl_packet import SSLPacket, SSLHandshakeClientHelloRecord, SSLExtensionServerName

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(message)s'))
stdout_handler.setFormatter(formatter)
log.addHandler(stdout_handler)


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
            log.info('Found host in client hello: {}'.format(host))
            return host
    return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--init-ca', dest='init_ssl_ca', action='store_true',
                        help='Initialize a CA')
    parser.add_argument('--whitelist', nargs='+')
    args = parser.parse_args()

    if args.init_ssl_ca:
        init_ssl_ca()
    else:
        if args.whitelist:
            whitelist = args.whitelist
        else:
            whitelist = []

        listening_port = 8443

        log.info('Started listening on {}'.format(listening_port))

        sock_ips_client = socket.socket()
        sock_ips_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_ips_client.bind(('0.0.0.0', listening_port))
        sock_ips_client.listen(3)

        while True:
            try:
                log.info('-' * 20)
                conn_ips_client, client_address = sock_ips_client.accept()
                log.info('Accepting new client {}'.format(client_address))

                init_pkt = conn_ips_client.recv(4096, socket.MSG_PEEK)
                init_pkt = SSLPacket.from_pkt(init_pkt)

                host = get_host(init_pkt)
                if not host:
                    log.info('Did not find host, continuing...')
                    continue

                sock_ips_world = socket.socket()

                if host not in whitelist:
                    log.info('Host not in whitelist')
                    try:
                        crt, key = generate_ssl(host)

                        sock_ips_world = ssl.wrap_socket(sock_ips_world)

                        conn_ips_client = ssl.wrap_socket(conn_ips_client, server_side=True, certfile=crt, keyfile=key)
                        conn_ips_client.setblocking(1)
                    except (ssl.SSLError, OSError) as e:
                        log.debug('Could not wrap client - ips socket: {}'.format(e))
                        continue

                    try:
                        conn_ips_client.do_handshake()
                        conn_ips_client.setblocking(0)
                    except (ssl.SSLError, OSError) as e:
                        log.debug('Could not do SSL handshake: {}'.format(e))
                        continue
                else:
                    log.info('Host is in whitelist')

                try:
                    sock_ips_world.connect((host, 443))
                    sock_ips_world.setblocking(1)
                    sock_ips_world.settimeout(3)
                except ssl.SSLWantReadError as e:
                    log.debug('Could not connect remote server: {}'.format(e))
                    break

                log.info('Started data interaction...')
                while True:
                    try:
                        data_client = conn_ips_client.recv(4096)
                        log.debug(' <- Received data from client')
                    except ssl.SSLError as e:
                        log.debug('Could not read from client: {}'.format(e))
                        break

                    if not data_client:
                        break

                    try:
                        sock_ips_world.sendall(data_client)
                        log.debug('     -> Sent data to world')
                    except BrokenPipeError as e:
                        log.error('Could not send data to world {}'.format(e))

                    while True:
                        try:
                            data_world = sock_ips_world.recv(4096)
                            log.debug('     <- Received data from world')
                        except (ssl.SSLWantReadError, socket.timeout) as e:
                            log.debug('Could not read from www: {}'.format(e))
                            break

                        try:
                            conn_ips_client.sendall(data_world)
                            log.debug(' -> Sent data to client')
                        except ssl.SSLWantWriteError as e:
                            log.debug('Error sending to client: {}'.format(e))

                        if not data_world:
                            break

                log.info('Closing {}'.format(host))
                sock_ips_world.close()
                conn_ips_client.close()

            except KeyboardInterrupt:
                sock_ips_client.close()
                log.info("Terminating")
                exit(0)
