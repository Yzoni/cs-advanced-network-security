Questions from assignment:

####Task 1:
The newly added ieee80211 module is able to parse IEEE802.11 packets. A malicious actor would send large amounts 
of deauthenticaiton or disassociation frames in order to achieve constant denial of service. The quantity of these 
frames is what could trigger suspicion. A possible alert configuration should thus keep track of the amount of 
deauthentication/disassociation frames that are exchanged between a host and AP. If this exceeds a certain threshold
an alert should be triggered by the IPS.

####Task 2:
Detection of ARP-request replay attack on WEP encrypted network.

The implemented alert configuration monitors for multiple duplicate frames with duplicate IVs, not rebroadcasts 
but actual duplicates. Although not implemented a possible optimization would be to also scan for bursts of 
deauthentication/disassociation frames.


####Task 3:
In the Netherlands, the wetboek van strafrecht has the following relevant law about, interfering with third party networks:

Artikel 138b

1. Met gevangenisstraf van ten hoogste twee jaren of geldboete van de vierde categorie wordt gestraft hij 
   die opzettelijk en wederrechtelijk de toegang tot of het gebruik van een geautomatiseerd werk belemmert 
   door daaraan gegevens aan te bieden of toe te zenden.

There is no exception for defensive blocking on defensive grounds.

####Task 4:


####Task 5