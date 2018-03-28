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


#### Risk assessment when deploying such application in practice:
When above solution is for instance used in an organization to be able to deep packet inspection it 
creates a couple of new risks.

The first risk comes from the custom certificate necessary on the client. This brings great responsibility 
to the organization to keep the CA key safe. If the key gets compromised by someone with bad intentions he
is able to create trusted certificates for domains they do not own. In combination with a MiTM attack,
they are able exercise the same functionality as the `ssl_mitm` application demonstrated here, thus being able 
to read all client data to and from a server in plaintext.

The second risk is that from possibly multiple hosts all data is now visible on a single point, the server that 
contains the `ssl_mitm` application. If this server gets compromised all data in the network is visible to the 
intruder.

To mitigate the risk of the key being compromised the key should be placed on a different server which only purpose
is to sign certificates, so only certificates are allowed to (arrive) and leave this system.

In order to mitigate the risk of data compromise when the MiTM server gets compromised it should first of all be
placed in a DMZ, no other data then should be allowed to flow from or to this MiTM server than SSL data, so no remote
access. The only risk that this service then has is a bug in the MiTM software that could be exploited trough a 
malicious SSL packet that is analyzed.

