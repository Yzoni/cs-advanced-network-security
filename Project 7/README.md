## Python modular Intrusion Prevention System (IPS)


#### Preparation:
All incoming HTTPS traffic needs to be directed to the tunnel application:

```bash
sysctl -w net.ipv4.ip_forward=1

iptables -t nat -F
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
```

#### Usage:
```bash
usage: ssl_mitm.py [-h] [--init-ca] [--whitelist WHITELIST [WHITELIST ...]]

Process some integers.

optional arguments:
  -h, --help            show this help message and exit
  --init-ca             Initialize a CA
  --whitelist WHITELIST [WHITELIST ...]
```

#### Example:
```bash
python3 ssl_mitm.py --whitelist www.aivd.nl yrck.nl
```