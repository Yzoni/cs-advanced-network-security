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

The log is saved as txt.


Questions from assignment:

####Task 1:
For each source/destination a separate counter matrix is used. The timer for the visualizations
is zero. This is for demonstration purposes, it just recreates the visualizations after each update
to the matrix.

The visualizations can be found in the `out_pred_ssl` folder, here they are aggregated on ip, because tcp
session uses a different port.

####Task 2:
Fingerprints for 5 different applications were created and can be found in the `modules/predict_ssl/samples` folder.

The code used to create the fingerprints is in `modules/predict_ssl/predict_ssl_train.py`. Each fingerprint consists of
multiple calls to the application but with cache, so subsequent calls might use the cache for the `certificate`, in
order to shortcut the handshake. Each application is recorded for 15 seconds.

The following applications were used:
```python
apps = [
    'tweakers.net',
    'en.wikipedia.org',
    'about.gitlab.com',
    'docs.python.org',
    'edition.cnn.com',
]
```

When we the visualizations we see that the `tweakers.net` always goes trough the whole handshake and does not shortcut by
using the cache. The opposite we see for `en.wikipedia.org` which uses for almost 40 percent of the time. `CNN` sends
multiple alerts after each other. The rest of applications all close with a single alert. It is also the only application 
that has a certificate status message. Its interesting wikipedia does not have a new
session message, a possible explanation could be that the session was not long enough.

####Task 3:
The same script as for Task 2 can be used to generate training data, just with different parameters.

Runnable by:

```bash
sudo python modules/predict_ssl/predict_ssl_train.py eno1 --traces-per-app 30 --time-per-trace 15
```

The 5 fold crossvalidation can be found at `modules/predict_ssl/predict_ssl_test.py`. An accuracy of 100 percent was
achieved. This high percentage can be explained from the relative few amount of applications and there is hardly
any difference between executions when collecting data. The data used is in the `modules/predict_ssl/samples` folder.


####Task 4:
There is something in the `modules/predict_pop/` directory. It parses the supplied pop pcap file. But does not yet
do any analysis.