#include <stdio.h>
#include <stdlib.h>
#include <json-c/json.h>

#include <pcap.h>
#include <netinet/in.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <zconf.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

#define SIZE_UDP_HEADER 8

#define SIZE_DNS_HEADER 12

/*
 * IP and TCP headers taken from:
 *
 * https://www.tcpdump.org/pcap.html
 */

/* IP header */
struct ip_header {
    u_char ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct udp_header {
    uint16_t th_sport;
    uint16_t th_dport;
    uint16_t th_length;
    uint16_t th_checksum;
};

struct tcp_header {
    uint16_t th_sport;               /* source port */
    uint16_t th_dport;               /* destination port */
    uint32_t th_seq;                 /* sequence number */
    uint32_t th_ack;                 /* acknowledgement number */
    u_char th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_window;                 /* window */
    u_short th_checksum;                 /* checksum */
    u_short th_urgentp;                 /* urgent pointer */
};

struct dns_question_record {
    char *name;
    uint16_t type;
    uint16_t class;
};

struct dns_header {
    uint16_t dns_query_id;
    uint8_t dns_rd : 1;
    uint8_t dns_tc : 1;
    uint8_t dns_aa : 1;
    uint8_t dns_opcode : 4;
    uint8_t dns_qr : 1;
    uint8_t dns_rcode : 4;
    uint8_t dns_000 : 3;
    uint8_t dns_ra : 1;
    uint16_t dns_question_count;
    uint16_t dns_answer_count;
    uint16_t dns_auth_count;
    uint16_t dns_addt_count;
};

/*
 * https://github.com/agavrel/42-Bitwise_Operators/blob/master/1.1_printing_bits.c
 */
void print_bits(unsigned char octet) {
    int i;

    i = 128;
    while (octet >= 0 && i) {
        (octet / i) ? write(1, "1", 1) : write(1, "0", 1);
        (octet / i) ? octet -= i : 0;
        i /= 2;
    }
}

uint16_t parse_labels(const u_char *dns_qr, char *label_buffer) {
    const u_char *current_octet = dns_qr + 1;
    const u_char *next_octet = dns_qr + 2;

    uint16_t label_length = 0;
    u_int8_t sub_label_length = *(current_octet - 1);
    while (*next_octet != 0) {

        if (sub_label_length == 0) {
            label_buffer[label_length] = '.';
            sub_label_length = *current_octet;
        } else {
            label_buffer[label_length] = *current_octet;
            --sub_label_length;
        }

        ++current_octet;
        ++next_octet;
        ++label_length;
    }
    label_buffer[label_length] = *current_octet;
    printf("%s", label_buffer);
    return label_length;
}

void write_tcp_dns(json_object *packet_object,
                   const struct ip_header *ip,
                   const struct tcp_header *tcp,
                   const struct dns_header *dns) {
    // Fill ip header
    json_object *dns_packet_ip = json_object_new_object();
    json_object *srcip = json_object_new_string(inet_ntoa(ip->ip_src));
    json_object *srcport = json_object_new_int(ntohs(tcp->th_sport));
    json_object *dstip = json_object_new_string(inet_ntoa(ip->ip_dst));
    json_object *dstport = json_object_new_int(ntohs(tcp->th_dport));
    json_object_object_add(dns_packet_ip, "srcip", srcip);
    json_object_object_add(dns_packet_ip, "srcport", srcport);
    json_object_object_add(dns_packet_ip, "dstip", dstip);
    json_object_object_add(dns_packet_ip, "dstport", dstport);

    json_object *dns_header = json_object_new_object();
}

void write_udp_dns_json(json_object *packet_object,
                        const struct ip_header *ip,
                        const struct udp_header *udp,
                        const struct dns_header *dns) {

    // Fill ip header
    json_object *dns_packet_ip = json_object_new_object();
    json_object *srcip = json_object_new_string(inet_ntoa(ip->ip_src));
    json_object *srcport = json_object_new_int(ntohs(udp->th_sport));
    json_object *dstip = json_object_new_string(inet_ntoa(ip->ip_dst));
    json_object *dstport = json_object_new_int(ntohs(udp->th_dport));
    json_object_object_add(dns_packet_ip, "srcip", srcip);
    json_object_object_add(dns_packet_ip, "srcport", srcport);
    json_object_object_add(dns_packet_ip, "dstip", dstip);
    json_object_object_add(dns_packet_ip, "dstport", dstport);

    // Fill DNS header
    json_object *dns_header = json_object_new_object();
    json_object *id = json_object_new_int(ntohs(dns->dns_query_id));
    json_object *qr = json_object_new_boolean(ntohs(dns->dns_qr));
//    json_object *opcode = json_object_new_string(dns->dns_opcode);
    json_object *aa = json_object_new_boolean(ntohs(dns->dns_aa));
    json_object *tc = json_object_new_boolean(ntohs(dns->dns_tc));
    json_object *rd = json_object_new_boolean(ntohs(dns->dns_rd));
    json_object *ra = json_object_new_boolean(ntohs(dns->dns_ra));
//    json_object *rcode = json_object_new_string(ntohs(dns->dns_rcode));
    json_object *qdcount = json_object_new_int(ntohs(dns->dns_question_count));
    json_object *nscount = json_object_new_int(ntohs(dns->dns_answer_count));
    json_object *ancount = json_object_new_int(ntohs(dns->dns_auth_count));
    json_object *arcount = json_object_new_int(ntohs(dns->dns_addt_count));
    json_object_object_add(dns_header, "id", id);
    json_object_object_add(dns_header, "qr", qr);
//    json_object_object_add(dns_header, "qr", opcode);
    json_object_object_add(dns_header, "aa", aa);
//    json_object_object_add(dns_header, "ad", ad);
    json_object_object_add(dns_header, "tc", tc);
    json_object_object_add(dns_header, "rd", rd);
    json_object_object_add(dns_header, "ra", ra);
//    json_object_object_add(dns_header, "cd", cd);
//    json_object_object_add(dns_header, "rcode", rcode);
    json_object_object_add(dns_header, "qdcount", qdcount);
    json_object_object_add(dns_header, "nscount", nscount);
    json_object_object_add(dns_header, "ancount", ancount);
    json_object_object_add(dns_header, "arcount", arcount);

    // Fill questions
    // Fill answers
    // Fill authority
    // Fill additional

    // Fill packet
    json_object_object_add(packet_object, "ipv4", dns_packet_ip);
    json_object_object_add(packet_object, "header", dns_header);
}

void got_packet(u_char *jobj, const struct pcap_pkthdr *header, const u_char *packet) {
    static int packet_counter = 0;
    int i;
    int size_ip;

    const struct ip_header *ip;
    const struct tcp_header *tcp;
    const struct udp_header *udp;
    const struct dns_header *dns;
//    const struct dns_question_record *dns_qr;
//    const struct dns_answer_record *dns_ar;
//    const struct dns_auth_record *dns_authr;
//    const struct dns_addt_record *dns_addtr;
    char label_buffer[30] = {0};

    packet_counter++;
    printf("\nPacket number %d:\n", packet_counter);

    // Init packet in json
    json_object *packet_object = json_object_new_object();
    char packet_count_str[80];
    sprintf(packet_count_str, "packet_%d", packet_counter);
    puts(packet_count_str);

    ip = (struct ip_header *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;

    switch (ip->ip_p) {
        case IPPROTO_TCP:
            printf("Protocol: TCP\n");
            tcp = (struct tcp_header *) (packet + SIZE_ETHERNET + size_ip);
//            write_udp_dns_json(packet_object, ip, tcp, dns);
            return;
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            udp = (struct udp_header *) (packet + SIZE_ETHERNET + size_ip);
            dns = (struct dns_header *) (packet + SIZE_ETHERNET + size_ip + SIZE_UDP_HEADER);

            write_udp_dns_json(packet_object, ip, udp, dns);
            json_object_object_add((struct json_object *) jobj, packet_count_str, packet_object);

            for (i = 0; i < ntohs(dns->dns_question_count); i++) {
                u_char *dns_qr = (u_char *) (packet + SIZE_ETHERNET + size_ip + SIZE_UDP_HEADER +
                                             SIZE_DNS_HEADER);
                parse_labels(dns_qr, label_buffer);
            }
            for (i = 0; i < ntohs(dns->dns_answer_count); i++) {

            }

            return;
        default:
            printf("Protocol: Non-Relevant\n");
            return;
    }
}

void parse_capture(pcap_t *handle, char *out_file) {
    json_object *jobj = json_object_new_object();
    pcap_loop(handle, 10, got_packet, (u_char *) jobj);

    json_object_to_file(out_file, jobj);
    printf("The json object created: %sn", json_object_to_json_string(jobj));
}

void capture_offline(char *pcap_file, char *out_file) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    parse_capture(handle, out_file);
    pcap_close(handle);
}

void capture_live(char *out_file) {
    char errbuf[PCAP_ERRBUF_SIZE];

    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    char str[80];
    sprintf(str, "Capture device name: %s\n", dev);
    puts(str);

    pcap_t *handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    parse_capture(handle, out_file);
    pcap_close(handle);
}

int main(int argc, char **argv) {
    char *json_out = argv[2];

    if (argc == 3) {
        char *pcap_file = argv[1];
        capture_offline(pcap_file, json_out);
    } else {
        printf("No arguments given, capture live\n");
        capture_live(json_out);
    }

    return 0;
}