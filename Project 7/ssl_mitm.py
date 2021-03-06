import socket
import ssl
import subprocess
import argparse
import logging as logging
import sys
import threading
import multiprocessing
import re
import time

from ssl_packet import SSLPacket, SSLHandshakeClientHelloRecord, SSLExtensionServerName

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(message)s'))
log.addHandler(stdout_handler)


def init_ssl_ca():
    subprocess.call(['openssl', 'genrsa', '-out', 'myCA.key', '2048'])
    subprocess.call(['openssl', 'req', '-x509', '-new', '-nodes', '-key', 'myCA.key',
                     '-sha256', '-days', '1825', '-out', 'myCA.pem', '-subj',
                     '/C=NL/ST=ZuidHolland/L=Rotterdam/O=SecOps/OU=ITDep/CN=SecOps'])


def generate_ssl(host):
    subprocess.call(['truncate', '-s', '0', './demoCA/index.txt'])
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


def setup_listening_sock(port):
    sock_ips_client = socket.socket()
    sock_ips_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_ips_client.bind(('0.0.0.0', port))
    sock_ips_client.listen(3)
    return sock_ips_client


def handle_client(conn_ips_client, client_address, ssl_enabled=True):
    init_pkt = conn_ips_client.recv(4096, socket.MSG_PEEK)

    if ssl_enabled:
        try:
            init_pkt = SSLPacket.from_pkt(init_pkt)
            host = get_host(init_pkt)
        except Exception:
            log.info('Could not read init ssl packet')
            return 1
    else:
        host = re.search(r"Host: (.+)\r\n", init_pkt.decode()).group(1)

    if not host:
        log.info('Did not find host, continuing...')
        return 1

    sock_ips_world = socket.socket()

    if host not in whitelist and ssl_enabled:
        log.info('Host not in whitelist')
        try:
            crt, key = generate_ssl(host)

            sock_ips_world = ssl.wrap_socket(sock_ips_world)

            conn_ips_client = ssl.wrap_socket(conn_ips_client, server_side=True, certfile=crt, keyfile=key)
            conn_ips_client.setblocking(1)
        except (ssl.SSLError, OSError) as e:
            log.debug('Could not wrap client - ips socket: {}'.format(e))
            return 1

        try:
            conn_ips_client.do_handshake()
            conn_ips_client.setblocking(0)
        except (ssl.SSLError, OSError) as e:
            log.debug('Could not do SSL handshake: {}'.format(e))
            return 1
    else:
        log.info('Host is in whitelist')

    try:
        if ssl_enabled:
            sock_ips_world.connect((host, 443))
        else:
            sock_ips_world.connect((host, 80))

        sock_ips_world.setblocking(1)
        sock_ips_world.settimeout(3)
    except ssl.SSLError as e:
        log.debug('Could not connect remote server: {}'.format(e))
        return 1

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
            log.info('Request: {}'.format(data_client.decode().split('\n')[0]))
        except Exception:
            log.info('Could not decode client request, not printing')

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
            except (ssl.SSLWantWriteError, BrokenPipeError) as e:
                log.debug('Error sending to client: {}'.format(e))

            if not data_world:
                break

    log.info('Closing {}'.format(host))
    sock_ips_world.close()
    conn_ips_client.close()
    return 0


def listen_for_clients(sock, ssl_enabled):
    while True:
        log.info('-' * 20)
        conn_ips_client, client_address = sock.accept()
        log.info('Accepting new client {}'.format(client_address))

        threading.Thread(target=handle_client, args=(conn_ips_client, client_address, ssl_enabled)).start()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SSL MiTM')
    parser.add_argument('--init-ca', dest='init_ssl_ca', action='store_true',
                        help='Initialize a CA')
    parser.add_argument('--whitelist', nargs='+',
                        help='Whitelist hosts that pass directly without interception')
    args = parser.parse_args()

    if args.init_ssl_ca:
        init_ssl_ca()
    else:
        if args.whitelist:
            whitelist = args.whitelist
        else:
            whitelist = []

        http_listening_port = 8080
        https_listening_port = 8443

        log.info('Started listening on for HTTPS connections {}'.format(https_listening_port))
        https_sock_ips_client = setup_listening_sock(https_listening_port)

        log.info('Started listening on for HTTP connections {}'.format(http_listening_port))
        http_sock_ips_client = setup_listening_sock(http_listening_port)

        https_process = multiprocessing.Process(target=listen_for_clients, args=(https_sock_ips_client, True))
        http_process = multiprocessing.Process(target=listen_for_clients, args=(http_sock_ips_client, False))

        https_process.start()
        http_process.start()

        while True:
            try:
                time.sleep(1)
                pass
            except KeyboardInterrupt:
                https_process.terminate()
                http_process.terminate()
                log.info("Terminating")
                exit(0)
