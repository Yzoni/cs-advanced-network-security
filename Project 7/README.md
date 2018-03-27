## SSL MiTM


#### Preparation:
First the traffic of the victims host needs to be directed to the host running this application. The victim
also needs to have the root CA installed for which the certificates this application generates are signed with
so they appear legitimate for the victim (green lock in browser). A root certificate can be generated with this
application trough:

```bash
pytho3 --init-ca
```

Then install the myCA.pem on the victim.


Second on the host where this application runs, all incoming HTTPS traffic needs to be directed to the application:

```bash
sysctl -w net.ipv4.ip_forward=1  # Make sure it is enabled in /etc/sysctl.conf
sysctl --system

iptables -t nat -F
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
```

#### Usage:
```bash
usage: ssl_mitm.py [-h] [--init-ca] [--whitelist WHITELIST [WHITELIST ...]]

SSL MiTM

optional arguments:
  -h, --help            show this help message and exit
  --init-ca             Initialize a CA
  --whitelist WHITELIST [WHITELIST ...]
                        Whitelist hosts that pass directly without
                        interception
```

#### Example:
```bash
python3 ssl_mitm.py --whitelist www.aivd.nl yrck.nl
```