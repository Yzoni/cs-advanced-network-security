Permitted scenarios:
* Sending ARP requests
* Unsolicited ARP reply

Error scenarios:
* ARP packets on the link have to be properly formatted
* MAC addresses need to be valid

Notice scenarios:
* ARP requests have to be sent to the broadcast address
* ARP responses have to be sent to the unicast address of the sender and are not returned to the link layer broadcast address
* ARP packets are internally consistant in that the MAC addresses of the link layer header match those that are included in the ARP packet


Check if all hosts follow RFC826 (determine if hosts discard certain ARP replies)