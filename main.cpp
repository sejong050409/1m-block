#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
#include "headers.h"

#include <unordered_set>
#include <fstream>
#include <sstream>
#include <string>
#include <chrono>

using namespace std;

unordered_set<string> blocked_hosts;

string trim(string s) {
    s.erase(0, s.find_first_not_of(" \r\n\t"));
    s.erase(s.find_last_not_of(" \r\n\t") + 1);
    return s;
}

void load_sites(const char* filename) {
    ifstream file(filename);
    string line;

    while (getline(file, line)) {
        stringstream ss(line);
        string rank, domain;

        getline(ss, rank, ',');
        getline(ss, domain);

        domain = trim(domain);

        if (!domain.empty())
            blocked_hosts.insert(domain);
    }
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("id=%u ", id);
    }

    int ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d\n", ret);

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);

    unsigned char *payload;
    int len = nfq_get_payload(nfa, &payload);

    if (len >= 0) {
        ip_header *ip = (ip_header *)payload;
        int ip_header_len = (ip->ver_ihl & 0x0F) * 4;

        if (ip->protocol != 6)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        tcp_header *tcp = (tcp_header *)(payload + ip_header_len);

        if (ntohs(tcp->dst_port) != 80)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        int tcp_header_len = ((tcp->offset_reserved >> 4) & 0x0F) * 4;

        unsigned char *http = payload + ip_header_len + tcp_header_len;

        if (http >= payload + len)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        int http_len = len - ip_header_len - tcp_header_len;

        char *host = strstr((char *)http, "Host:");

        if (host) {
            host += 5;

            while (*host == ' ') host++;
            char *end = strstr(host, "\r\n");

            if (end) {
                char domain[256] = {0};
                int host_len = end - host;

                if (host_len < (int)sizeof(domain)) {
                    strncpy(domain, host, host_len);
                    domain[host_len] = '\0';

                    string host_str(domain);

                    host_str = trim(host_str);

                    if (host_str.substr(0, 4) == "www.")
                        host_str = host_str.substr(4);

                    size_t colon = host_str.find(':');
                    if (colon != string::npos)
                        host_str = host_str.substr(0, colon);

                    auto t1 = std::chrono::high_resolution_clock::now();

                    bool found = (blocked_hosts.find(host_str) != blocked_hosts.end());

                    auto t2 = std::chrono::high_resolution_clock::now();
                    auto dt = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1);

                    printf("[Lookup] %s -> %ld ns\n", host_str.c_str(), dt.count());

                    if (found) {
                        printf("BLOCKED: %s\n", host_str.c_str());
                        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                    }
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("syntax: 1m-block <csv file>\n");
        return -1;
    }

    blocked_hosts.reserve(1000000);

    printf("[*] Loading CSV...\n");

    auto load_start = std::chrono::high_resolution_clock::now();

    load_sites(argv[1]);

    auto load_end = std::chrono::high_resolution_clock::now();
    auto load_time = std::chrono::duration_cast<std::chrono::milliseconds>(load_end - load_start);

    printf("[*] Loaded %lu sites\n", blocked_hosts.size());
    printf("[*] Load time: %ld ms\n", load_time.count());

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    nfq_unbind_pf(h, AF_INET);
    nfq_bind_pf(h, AF_INET);

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

    fd = nfq_fd(h);

     printf("[*] Running...\n");

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }

        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }

        perror("recv failed");
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
