##Python PCAP parser for DNS packets

####Usage:
```bash
python3 /path/to/pcap_file.pcap /path/to/json_out.json
```

or

```bash
run.sh /path/to/pcap_file.pcap /path/to/json_out.json
```

####As per assignment:

Two ways to filter for only TCP packets by BPF string: it could be done trough either the `ip proto tcp` 
string or the abbreviation `tcp`.

