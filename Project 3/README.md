## Python modular Intrusion Prevention System (IPS)

Added IEEE802.11 Parsing

#### Usage:

Directly:
```bash
python3 ips.py [-h] pcap_in log_out
```
The `pcap_in` argument can be a saved PCAP file or a live device.

or to install dependencies before running:
```bash
run.sh in_pcap out_log
```

The log is saved in JSON format

#### Tests:
Tests can be run per module with PyTest, for instance:
```bash
pytest modules/ieee80211
```


Questions from assignment:

####Task 1:
The newly added ieee80211 module is able to parse IEEE802.11 packets. A malicious actor would send large amounts 
of deauthenticaiton or disassociation frames in order to achieve constant denial of service. The quantity of these 
frames is what could trigger suspicion. A possible alert configuration should thus keep track of the amount of 
deauthentication/disassociation frames that are exchanged between a host and AP. If this exceeds a certain threshold
an alert should be triggered by the IPS.

####Task 2:
Detection of ARP-request replay attack on WEP encrypted network.

The implemented alert configuration monitors for multiple duplicate frames with duplicate IVs (not rebroadcasts, 
but actual duplicates). It stores all IVs originating from clients and counts them. If the number of duplicate IVs 
exceed a threshold, an Error response is emitted and the counter is reset. Although not implemented a possible 
optimization would be to also scan for bursts of deauthentication/disassociation frames.


####Task 3:
In the Netherlands, the wetboek van strafrecht has the following relevant law about, interfering with third 
party networks:

Artikel 138b

1. Met gevangenisstraf van ten hoogste twee jaren of geldboete van de vierde categorie wordt gestraft hij 
   die opzettelijk en wederrechtelijk de toegang tot of het gebruik van een geautomatiseerd werk belemmert 
   door daaraan gegevens aan te bieden of toe te zenden.

There is no exception for defensive blocking on defensive grounds.

####Task 4:
For authentication and deauthentication frames the receiver cannot be certain that the frame was sent by 
the base station.

If a client is in the same network and thus knows the pairwise master key in wpa(2)-personal he should be able
to spoof another client in the network. For broadcast messages he does not need anything anything more than
the GTK. This key gives every legitimate client the ability to decrypt all broadcast traffic.
 
To spoof unicast messages the spoofer will need to have captured the ANonce and the SNonce during the 4-way
handshake of the client have wants to spoof, with this he would be able to derive the PTK.

####Task 5