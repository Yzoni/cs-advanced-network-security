## Python modular Intrusion Prevention System (IPS)

#### Usage:

Directly:
```bash
python3 ips.py [-h] [--arp-acl-config ARP_CONFIG] pcap_in log_out
```
The `pcap_in` argument can be a saved PCAP file or a live device.

or to install dependencies before running:
```bash
run.sh pcap_in, log_out path_to_acl_config
```

The log is saved in JSON format

#### Tests:
Tests can be run per module with PyTest, for instance:
```bash
pytest modules/arp
```

#### ARP scenarios:

Permitted scenarios:
* Unsolicited ARP reply

Error scenarios:
* ARP packets on the link are not properly formatted
* MAC addresses are not valid

Notice scenarios:
* ARP requests are not sent to the broadcast address
* ARP responses are not sent to the unicast address of the sender
* ARP packets are internally consistant in the sense that the MAC addresses of the link layer header matches those that are included in the ARP packet
* Clients do not follow RFC826 (eg if hosts discard certain ARP replies)