## SSL MiTM

Application that makes inspecting HTTPS traffic possible when placed between a host and the internet. This
is done by creating two tunnels, one between the host and this application and one between the application
and the internet. To demonstrate all traffic is readable, the request URL from the client is visible 
in the log.

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
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080 
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

When above solution is for instance used in an organization to be able to deep packet inspection it 
creates a couple of new risks.

The first risk comes from the custom certificate necessary on the client. This brings great responsibility 
to the organization to keep the CA key safe. If the key gets compromised it is possible for an attacket to 

The second risk is that from possibly multiple hosts is now visible on a single point, the server that contains
this application. 