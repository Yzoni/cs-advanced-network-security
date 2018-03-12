import ipaddress
from dnslib import *
import subprocess
import progressbar
import random
from multiprocessing import Process, Queue
import timeit
from collections import defaultdict
import matplotlib.pyplot as plt
import csv
from datastructures.bloomfilter import BloomFilter
from random import shuffle
import time


def send_dns_packet():
    q = DNSRecord(q=DNSQuestion("abc.com", QTYPE.CNAME))
    a = q.reply()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('localhost', 53))
    while True:
        s.sendto(a.pack(), ('localhost', 9999))


def generate_random_ip_list():
    bar = progressbar.ProgressBar()
    random.seed(42)
    with open('ip.txt', mode='w') as f:
        for i in bar(range(2000000)):
            f.write(str(ipaddress.ip_address(random.randint(1, 4294967296))) + '\n')


def start_server(queue, max_packets):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('localhost', 9999))

    started_receiving = False
    packet_count = 0
    while True:
        data, peer = sock.recvfrom(8192)

        if not started_receiving:
            start_time = timeit.default_timer()

        started_receiving = True
        packet_count += 1

        if packet_count > max_packets:
            queue.put(timeit.default_timer() - start_time)
            return


def write_dict_to_csv(csv_file, n_measurements, dict_data):
    with open(csv_file, 'w') as f:
        f.write(','.join(dict_data.keys()) + '\n')
        for n in range(n_measurements):
            row = list()
            for k, v in dict_data.items():
                row.append(str(dict_data[k][n]))
            f.write(', '.join(row) + '\n')


def generate_rules():
    data = defaultdict(list)

    t2 = Process(target=send_dns_packet)
    t2.start()
    queue = Queue()

    max_ip = 20000
    step_ip = 1000
    measurements = 3
    max_packets = 10000

    flush_filter()
    with open('ip.txt', mode='r') as f:
        with progressbar.ProgressBar(max_value=max_ip) as bar:
            for idx, ip in enumerate(f):

                subprocess.call('iptables -A INPUT -s ' + ip.rstrip() + ' -i lo -j DROP', shell=True)

                if idx % step_ip == 0:
                    for i in range(measurements):
                        t1 = Process(target=start_server, args=(queue, max_packets))
                        t1.start()

                        data[str(idx)].append(queue.get())

                        t1.join()
                    write_dict_to_csv('output_data.csv', measurements, dict(data))

                if idx > max_ip:
                    return

                bar.update(idx)

    t2.terminate()


def generate_ipset_rules():
    # https://unix.stackexchange.com/questions/258232/mass-ip-blocking

    data = defaultdict(list)

    t2 = Process(target=send_dns_packet)
    t2.start()
    queue = Queue()

    max_ip = 20000
    step_ip = 1000
    measurements = 3
    max_packets = 10000

    flush_filter()

    subprocess.call('ipset destroy blockips', shell=True)
    subprocess.call('ipset create blockips iphash', shell=True)
    subprocess.call('iptables -A INPUT -m set --match-set blockips -i lo -j DROP', shell=True)
    with open('ip.txt', mode='r') as f:
        with progressbar.ProgressBar(max_value=max_ip) as bar:
            for idx, ip in enumerate(f):

                subprocess.call('ipset -A blockips ' + ip.rstrip(), shell=True)

                if idx % step_ip == 0:
                    for i in range(measurements):
                        t1 = Process(target=start_server, args=(queue, max_packets))
                        t1.start()

                        data[str(idx)].append(queue.get())

                        t1.join()
                    write_dict_to_csv('output_data.csv', measurements, dict(data))

                if idx > max_ip:
                    return

                bar.update(idx)

    t2.terminate()


def flush_filter():
    subprocess.call('sudo iptables -F INPUT', shell=True)


def do_plot():
    def get_data(file):
        with open(file, mode='r') as f:
            reader = csv.reader(f)
            d = defaultdict(list)
            header = next(reader)
            for row in reader:
                for h, e in zip(header, row):
                    d[h].append(e)

        x_axis = list()
        y_axis = list()
        y_error = list()
        for k, v in d.items():
            x_axis.append(int(k))

            y = [float(i) for i in v]
            y_axis.append((sum(y) / len(y)) / 10000)
            y_error.append((max(y) - min(y)) / 10000)
        return x_axis, y_axis, y_error

    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.set_ylabel('Time (s)')
    ax.set_xlabel('# IPtable rules')

    x_axis, y_axis, y_error = get_data('task1.csv')
    task1 = ax.errorbar(x_axis, y_axis, yerr=y_error)

    x_axis, y_axis, y_error = get_data('task2-ipset.csv')
    task2_ipset = ax.errorbar(x_axis, y_axis, yerr=y_error)

    plt.legend([task1, task2_ipset], ['IPtables only', 'IPset'])
    plt.show()


def task_3():
    # Assuming the ip is in the data structure

    bloom_filter = BloomFilter(m=175000000, k=30)
    hash_table = dict()
    iptable_list = list()

    ip_lookup = list()

    with open('ip.txt', mode='r') as f, open('task3.csv', mode='w') as t3f:
        t3f.write('entries,bloom,hash,list\n')

        bar = progressbar.ProgressBar()
        for x in bar(range(int(2000000 / 100000))):
            for y in range(100001):
                ip = next(f)
                bloom_filter.add(ip)
                hash_table[ip] = True
                iptable_list.append(ip)
                ip_lookup.append(ip)

            shuffle(ip_lookup)

            start_bloom = time.time()
            for z in range(1000):
                bloom_filter.might_contain(ip_lookup[z])
            finish_bloom = (time.time() - start_bloom) / 1000

            start_hash = time.time()
            for z in range(1000):
                hash_table[ip_lookup[z]]
            finish_hash = (time.time() - start_hash) / 1000

            start_iptable = time.time()
            for z in range(1000):
                ip_lookup[z] in iptable_list
            finish_iptable = (time.time() - start_iptable) / 1000

            t3f.write('{},{},{},{}\n'.format(x * y, finish_bloom, finish_hash, finish_iptable))


def plot_task_3():
    x_axis = list()
    y_axis_bloom = list()
    y_axis_hash = list()
    y_axis_list = list()
    with open('task3.csv') as f:
        reader = csv.DictReader(f)
        for row in reader:
            x_axis.append(int(row['entries']))
            y_axis_bloom.append(float(row['bloom']))
            y_axis_hash.append(float(row['hash']))
            y_axis_list.append(float(row['list']))

    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.set_ylabel('Time (s)')
    ax.set_xlabel('Entries')

    ax.plot(x_axis, y_axis_bloom, label='Bloom filter')
    ax.plot(x_axis, y_axis_hash, label='Hash table')
    ax.plot(x_axis, y_axis_list, label='IPtable datastructure')

    handles, labels = ax.get_legend_handles_labels()
    ax.legend(handles, labels)
    plt.show()


if __name__ == '__main__':
    # flush_filter()
    # generate_rules()
    # generate_ipset_rules()
    # generate_random_ip_list()
    do_plot()
    # task_3()
    # plot_task_3()
