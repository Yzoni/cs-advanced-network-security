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
python3 ssl_mitm.py
```