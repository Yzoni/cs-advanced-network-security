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

#define CHECK_FIRST_TWO_BITS(n) (0xC0 & dns_start)

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

struct dns_resource_record {
    char *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    char *rdata;
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

const u_char *parse_labels(const u_char *dns_qr, char *label_buffer) {
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

    return ++next_octet;
}

void write_tcp_json(json_object *packet_object,
                    const struct ip_header *ip,
                    const struct tcp_header *tcp) {

    json_object *dns_packet_ip = json_object_new_object();
    json_object *srcip = json_object_new_string(inet_ntoa(ip->ip_src));
    json_object *srcport = json_object_new_int(ntohs(tcp->th_sport));
    json_object *dstip = json_object_new_string(inet_ntoa(ip->ip_dst));
    json_object *dstport = json_object_new_int(ntohs(tcp->th_dport));
    json_object_object_add(dns_packet_ip, "srcip", srcip);
    json_object_object_add(dns_packet_ip, "srcport", srcport);
    json_object_object_add(dns_packet_ip, "dstip", dstip);
    json_object_object_add(dns_packet_ip, "dstport", dstport);

    json_object_object_add(packet_object, "ipv4", dns_packet_ip);
}

void write_udp_json(json_object *packet_object,
                    const struct ip_header *ip,
                    const struct udp_header *udp) {

    json_object *dns_packet_ip = json_object_new_object();
    json_object *srcip = json_object_new_string(inet_ntoa(ip->ip_src));
    json_object *srcport = json_object_new_int(ntohs(udp->th_sport));
    json_object *dstip = json_object_new_string(inet_ntoa(ip->ip_dst));
    json_object *dstport = json_object_new_int(ntohs(udp->th_dport));
    json_object_object_add(dns_packet_ip, "srcip", srcip);
    json_object_object_add(dns_packet_ip, "srcport", srcport);
    json_object_object_add(dns_packet_ip, "dstip", dstip);
    json_object_object_add(dns_packet_ip, "dstport", dstport);

    json_object_object_add(packet_object, "ipv4", dns_packet_ip);
}

void write_dns_header_json(json_object *packet_object, const struct dns_header *dns) {

    const char *OPCODES[3] = {"QUERY", "IQUERY", "STATUS"};
    const char *RCODES[6] = {"NOERROR", "FORMATERROR", "SERVERFAILURE",
                             "NAMEERROR", "NOTIMPLEMENTED", "REFUSED"};

    json_object *dns_header = json_object_new_object();
    json_object *id = json_object_new_int(ntohs(dns->dns_query_id));
    json_object *qr = json_object_new_boolean(ntohs(dns->dns_qr));
    json_object *opcode = json_object_new_string(OPCODES[dns->dns_opcode]);
    json_object *aa = json_object_new_boolean(ntohs(dns->dns_aa));
    json_object *tc = json_object_new_boolean(ntohs(dns->dns_tc));
    json_object *rd = json_object_new_boolean(ntohs(dns->dns_rd));
    json_object *ra = json_object_new_boolean(ntohs(dns->dns_ra));
    json_object *rcode = json_object_new_string(RCODES[dns->dns_rcode]);
    json_object *qdcount = json_object_new_int(ntohs(dns->dns_question_count));
    json_object *nscount = json_object_new_int(ntohs(dns->dns_answer_count));
    json_object *ancount = json_object_new_int(ntohs(dns->dns_auth_count));
    json_object *arcount = json_object_new_int(ntohs(dns->dns_addt_count));
    json_object_object_add(dns_header, "id", id);
    json_object_object_add(dns_header, "qr", qr);
    json_object_object_add(dns_header, "opcode", opcode);
    json_object_object_add(dns_header, "aa", aa);
//    json_object_object_add(dns_header, "ad", ad); // not in rfc1035?
    json_object_object_add(dns_header, "tc", tc);
    json_object_object_add(dns_header, "rd", rd);
    json_object_object_add(dns_header, "ra", ra);
//    json_object_object_add(dns_header, "cd", cd); // not in rfc1035?
    json_object_object_add(dns_header, "rcode", rcode);
    json_object_object_add(dns_header, "qdcount", qdcount);
    json_object_object_add(dns_header, "nscount", nscount);
    json_object_object_add(dns_header, "ancount", ancount);
    json_object_object_add(dns_header, "arcount", arcount);

    json_object_object_add(packet_object, "header", dns_header);
}

const char *TYPES[17] = {"", "A", "NS", "MD", "MF",
                         "CNAME", "SOA", "MB", "MG",
                         "MR", "NULL", "WKS", "PTR",
                         "HINFO", "MINFO", "MX", "TXT"};

const char *CLASSES[5] = {"", "IN", "CS", "CH", "HS"};

void write_dns_question_record_json(json_object *jarray, struct dns_question_record dns_qr) {

    json_object *question = json_object_new_object();
    json_object *name = json_object_new_string(dns_qr.name);
    json_object *type = json_object_new_string(TYPES[dns_qr.type]);
    json_object *class = json_object_new_string(CLASSES[dns_qr.class]);
    json_object_object_add(question, "qname", name);
    json_object_object_add(question, "qtype", type);
    json_object_object_add(question, "qclass", class);

    json_object_array_add(jarray, question);
}

void write_dns_resource_record_json(json_object *jarray, struct dns_resource_record dns_rc) {

    json_object *resource = json_object_new_object();
    json_object *name = json_object_new_string(dns_rc.name);
    json_object *type = json_object_new_string(TYPES[dns_rc.type]);
    json_object *class = json_object_new_string(CLASSES[dns_rc.class]);
    json_object *ttl = json_object_new_int(dns_rc.ttl);
    json_object_object_add(resource, "qname", name);
    json_object_object_add(resource, "qtype", type);
    json_object_object_add(resource, "qclass", class);
    json_object_object_add(resource, "ttl", ttl);

    json_object_array_add(jarray, resource);
}

/*
 * Tests whether a name is a label or a offset to a label
 *  - Label when has two leading zero bits
 *  - Offset when has two leading one bits
 */
int check_first_two_bits(u_char dns_start) {
    printf("\n");
    print_bits(dns_start);
    printf("\n");
    print_bits(0xC0);
    printf("\n");
    print_bits((unsigned char) (0xC0 & dns_start));
    printf("\n");
    return (0xC0 & dns_start);
}

void got_packet(u_char *jobj, const struct pcap_pkthdr *header, const u_char *packet) {
    static int packet_counter = 0;
    int i;
    int size_ip;

    const struct ip_header *ip;
    const struct tcp_header *tcp;
    const struct udp_header *udp;
    const struct dns_header *dns;
    struct dns_question_record dns_qr;
    struct dns_resource_record dns_rc;

    packet_counter++;
    printf("\nPacket number %d:\n", packet_counter);

    // Init packet in json
    json_object *packet_object = json_object_new_object();
    char packet_count_str[63];
    sprintf(packet_count_str, "packet_%d", packet_counter);
    puts(packet_count_str);

    ip = (struct ip_header *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;

    switch (ip->ip_p) {
        case IPPROTO_TCP:
            printf("Protocol: TCP\n");
            tcp = (struct tcp_header *) (packet + SIZE_ETHERNET + size_ip);

            if (ntohs(tcp->th_dport) != 53 && ntohs(tcp->th_sport) != 53) {
                printf("Non standard DNS port not supported");
                return;
            }

            dns = (struct dns_header *) (packet + SIZE_ETHERNET + size_ip + SIZE_UDP_HEADER); // TODO
            write_tcp_json(packet_object, ip, tcp);
            break;
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            udp = (struct udp_header *) (packet + SIZE_ETHERNET + size_ip);

            if (ntohs(udp->th_dport) != 53 && ntohs(udp->th_sport) != 53) {
                printf("Non standard DNS port not supported");
                return;
            }

            dns = (struct dns_header *) (packet + SIZE_ETHERNET + size_ip + SIZE_UDP_HEADER);
            write_udp_json(packet_object, ip, udp);

            break;
        default:
            printf("Protocol: Non-Relevant\n");
            return;
    }

    write_dns_header_json(packet_object, dns);

    json_object *jarray_questions = json_object_new_array();
    u_char *dns_qr_start = (u_char *) (packet + SIZE_ETHERNET + size_ip + SIZE_UDP_HEADER +
                                       SIZE_DNS_HEADER);
    for (i = 0; i < ntohs(dns->dns_question_count); i++) {

        if (check_first_two_bits(*dns_qr_start) > 0) {
            // TODO get label from hash
        } else {
            char label_buffer[63] = {0};
            dns_qr_start = (u_char *) parse_labels(dns_qr_start, label_buffer);
            dns_qr.name = label_buffer;
            dns_qr.type = (uint16_t) (*dns_qr_start << 8 | *++dns_qr_start);
            dns_qr.class = (uint16_t) (*++dns_qr_start << 8 | *++dns_qr_start);
            // TODO add label to hash
        }
        write_dns_question_record_json(jarray_questions, dns_qr);
    }
    json_object_object_add(packet_object, "question", jarray_questions);

    json_object *jarray_answers = json_object_new_array();
    for (i = 0; i < ntohs(dns->dns_answer_count); i++) {

        // Increment to next start
        ++dns_qr_start;

        if (check_first_two_bits(*dns_qr_start) > 0) {
            printf("\nentered\n");
            printf("\n");
            dns_rc.name = "TODO";  // TODO get label from hash
            ++dns_qr_start; // TODO
            ++dns_qr_start; // TODO

            dns_rc.type = (uint16_t) (*dns_qr_start << 8 | *++dns_qr_start);
            dns_rc.class = (uint16_t) (*++dns_qr_start << 8 | *++dns_qr_start);
            dns_rc.ttl = (uint32_t) (*++dns_qr_start << 32 | *++dns_qr_start << 16 | *++dns_qr_start << 8 | *++dns_qr_start);

            dns_rc.rdlength = (uint16_t) (*++dns_qr_start << 8 | *++dns_qr_start);
            for (int j =0; j < dns_rc.rdlength; j++) {
                ++dns_qr_start; // TODO
            }

        } else {
            char label_buffer[63] = {0};
            dns_qr_start = (u_char *) parse_labels(dns_qr_start, label_buffer);
            dns_rc.name = label_buffer;
            dns_rc.type = (uint16_t) (*dns_qr_start << 8 | *++dns_qr_start);
            dns_rc.class = (uint16_t) (*++dns_qr_start << 8 | *++dns_qr_start);
            // TODO add label to hash
        }
        write_dns_resource_record_json(jarray_answers, dns_rc);
    }
    json_object_object_add(packet_object, "answers", jarray_answers);

    json_object *jarray_authority = json_object_new_array();
    json_object_object_add(packet_object, "authority", jarray_authority);

    json_object *jarray_additional = json_object_new_array();
    json_object_object_add(packet_object, "additional", jarray_additional);

    // Add complete packet data to json
    json_object_object_add((struct json_object *) jobj, packet_count_str, packet_object);
}

void parse_capture(pcap_t *handle, char *out_file) {
    json_object *jobj = json_object_new_object();
    pcap_loop(handle, 4, got_packet, (u_char *) jobj);

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