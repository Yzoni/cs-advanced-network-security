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

#### Legality of deploying a MiTM TLS decryption in a bussiness
In The Netherlands law that corresponds the closest to the question whether an employer is allowed to inspect all
internet traffic of an employee is the ground law of secrecy of correspondence. This rule however does not apply to
mail that is also directed to the business, so the business is allowed to read this mail.  

Multiple sources on the internet say that is allowed to do deep packet inspection on the business network, however
the employee has to be informed in advance of this practice. If the explicit consent, the packet inspection may
be seen as an attack on the employees privacy. I could however not find an explicit case in which the matter was 
handled in court.

European judges of the human rights court:
https://tweakers.net/nieuws/129221/bedrijf-moet-werknemer-tijdig-vertellen-over-monitoren-communicatie.html

Arnoud Engelfriet, Ict-jurist:
https://www.security.nl/posting/416510/Juridische+vraag%3A+mag+een+bedrijf+SSL-verkeer+via+zelfgemaakt+certificaat+filteren%3F
https://www.security.nl/posting/516591/Juridische+vraag%3A+Mag+mijn+werkgever+ssl-verkeer+decrypten+en+inspecteren+om+datalekken+te+voorkomen%3F

The Autoriteit Persoonsgegevens also has some information available regarding the inspection of employees and 
the influence on their privacy. This organization also says it is allowed to inspect employee internet traffic. However 
the employer needs a legitimate reason that is more important than the privacy of the employee. There also need 
to be no other alternatives that could achieve the same result. The employer also has to follow the law on the 
protection of personal data. The above application can be used, however again the employee needs be informed.

When an employer wants to inspect the employees internet traffic without him/her knowing he needs to have a 
reasonable suspicion of illegal activity and needs to inform the Autoriteit Persoonsgegevens. However packet 
inspection for legitimate reasons does not have to be done in secret, so this is not really relevant.
 
https://autoriteitpersoonsgegevens.nl/nl/onderwerpen/werk-uitkering/controle-van-personeel

#### Risk assessment when deploying such application in practice:
Although the implemented solution makes it possible to inspect SSL traffic in an origanization it introduces some new
risks to the network. In the following we will assess these new risks on an organization.

The first risk comes from the custom certificate necessary on the client. This brings great responsibility 
to the organization to keep the CA key safe. If the key gets compromised by someone with bad intentions he
is able to create trusted certificates for domains they do not own. In combination with a MiTM attack,
they are able exercise the same functionality as the `ssl_mitm` application demonstrated here, thus being able 
to read all client data to and from a server in plaintext.

The second risk is that from possibly multiple hosts all data is now visible on a single point, the server that 
contains the `ssl_mitm` application. If this server gets compromised all data in the network is visible in plain text
to the person accessing the server. The attack could either come from the internet or from one of the clients.

To mitigate the risk of the key being compromised the key should be placed on a different server which only purpose
is to sign certificates, so only certificates are allowed to (arrive) and leave this system.

In order to mitigate the risk of data compromise when the MiTM server gets compromised it should first of all be
placed in a DMZ, no other data then should be allowed to flow from or to this MiTM server than SSL data, so no remote
access, but also no access from any of the clients it monitors, incase any of these get compromized. The only risk 
that this service then has is a bug in the MiTM software that could be exploited trough a malicious packet that
is parsed and analyzed.

