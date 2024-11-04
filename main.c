#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<sys/socket.h>
#include<features.h>
#include<sys/ioctl.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<linux/if.h>
#include<string.h>
#include<strings.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<linux/ip.h>
#include<linux/tcp.h>

#define PACKET_BUF 2048

int create_raw_socket(int proto)
{
    int s_fd = socket(PF_PACKET, SOCK_RAW, htons(proto));
    if (s_fd == -1)
    {
        perror("err");
        printf("create socket error...exit\n");
        exit(-1);
    }
    else
        printf("socket successfully created\n");

    return s_fd;
}

void bind_raw_sock_to_ifce(char* device, int sd, int proto)
{
    struct sockaddr_ll ifce;
    struct ifreq ifr;

    bzero(&ifce, sizeof(ifce));
    bzero(&ifr, sizeof(ifr));

    strncpy((char*)&ifr.ifr_ifrn.ifrn_name, device, IFNAMSIZ);

    printf("device name %s\n", ifr.ifr_ifrn.ifrn_name);

    if ((ioctl(sd, SIOCGIFINDEX, &ifr)) == -1)
    {
        perror("err");
        printf("error getting ifce index...exit\n");
        exit(-1);
    }

    ifce.sll_family = AF_PACKET;
    ifce.sll_ifindex = ifr.ifr_ifru.ifru_ivalue; // ifce idx
    ifce.sll_protocol = htons(proto);

    if ((bind(sd, (struct sockaddr*)&ifce, sizeof(ifce))) == -1)
    {
        perror("err");
        printf("binding socket error...exit\n");
        exit(-1);
    }
    else
        printf("socket successfully binded to interface: %s\n", ifr.ifr_ifrn.ifrn_name);
}

void print_in_hex(char* msg, unsigned char* p, int len)
{
    printf("%s", msg);

    while (len--)
    {
        printf("%.2X ", *p);
        p++;
    }
    printf("\n");
}

const char* get_eth_protocol_name(unsigned short proto) 
{
    switch (proto) {
        case 0x0800:
            return "IPv4";
        case 0x0806:
            return "ARP";
        case 0x86DD:
            return "IPv6";
        default:
            return "Unknown Protocol";
    }
}

void print_dest_mac_address(unsigned char *mac) 
{
    printf("\n - Destination MAC Addr: %02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_src_mac_address(unsigned char *mac) 
{
    printf("\n - Source MAC Addr: %02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int parse_eth_headers(unsigned char *packet, int packet_size)
{
    struct ethhdr* eth_header;

    if (packet_size < sizeof(struct ethhdr))
    {
        printf("nothing to parse");
        return -1;
    }

    eth_header = (struct ethhdr*)packet;
    
    const char* proto = get_eth_protocol_name(ntohs(eth_header->h_proto));

    printf("----------------------------------");
    print_dest_mac_address(eth_header->h_dest);
    print_src_mac_address(eth_header->h_source);
    printf("\n - Protocol: %s\n", proto);
}

void parse_ip_headers(unsigned char *packet, int packet_size)
{
    struct ethhdr* eth_header;
    struct iphdr* ip_header;

    eth_header = (struct ethhdr*)packet;

    uint16_t ip_p = 2048;

    if (ntohs(eth_header->h_proto) == ip_p)
    {
        if (packet_size >= (sizeof(struct ethhdr) + ip_header->ihl*4))
        {
            ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));

            struct in_addr d_addr, s_addr;
            d_addr.s_addr = ip_header->daddr;
            s_addr.s_addr = ip_header->saddr;

            printf(" - Destination IP Addr: %s", inet_ntoa(d_addr));
            printf("\n - Source IP Addr: %s\n", inet_ntoa(s_addr));
        }
    }
}

void parse_tcp_headers(unsigned char *packet, int packet_size)
{
    struct ethhdr* eth_header;
    struct iphdr* ip_header;
    struct tcphdr* tcp_header;

    uint16_t ip_p = 2048;

    if (packet_size >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
    {
        eth_header = (struct ethhdr*)packet;

        if (ntohs(eth_header->h_proto) == ip_p)
        {
            ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));

            if (ip_header->protocol == IPPROTO_TCP)
            {
                tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4);

                printf(" - Destination PORT: %d", ntohs(tcp_header->dest));
                printf("\n - Source PORT: %d\n", ntohs(tcp_header->source));
            }
        }
    }
}

int is_tcp_ip_packet(unsigned char *packet, int packet_size)
{
    struct ethhdr* eth_header;
    struct iphdr* ip_header;

    uint16_t ip_p = 2048;

    eth_header = (struct ethhdr*)packet;

    if (ntohs(eth_header->h_proto) == ip_p)
    {
        ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));

        if (ip_header->protocol == IPPROTO_TCP)
        {
            return 1;
        } 
        else
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }

    return 0;
}

int parse_data(unsigned char *packet, int packet_size)
{
    struct ethhdr* eth_header;
    struct iphdr* ip_header;
    struct tcphdr* tcp_header;
    unsigned char *data;
    int d_len;

    if (packet_size > (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
    {
        ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
        data = (packet + sizeof(struct ethhdr) + ip_header->ihl*4 + sizeof(struct tcphdr));
        d_len = ntohs(ip_header->tot_len) - ip_header->ihl*4 - sizeof(struct tcphdr);

        if (d_len)
        {
            printf(" - Data Length: %d\n", d_len);
            print_in_hex(" - Data: ", data, d_len);
            return 1;
        }
        else 
        {
            printf("\nNo data in packet\n");
            return 0;
        }
    }
    else
    {
        printf("\nNo data in packet\n");
        return 0;
    }
    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        printf("Run failed. Exec commad: ./simple-network-sniffer.out <network interface> <packet's count>\n");
        exit(-1);
    }

    int sr_fd, len, packets_to_sniff;
    unsigned char packet_buffer[PACKET_BUF];
    struct sockaddr_ll packet_info;
    int packet_info_size = sizeof(packet_info);

    sr_fd = create_raw_socket(ETH_P_IP);
    bind_raw_sock_to_ifce(argv[1], sr_fd, ETH_P_IP);

    packets_to_sniff = atoi(argv[2]);

    while(packets_to_sniff--)
    {
        len = recvfrom(sr_fd, packet_buffer, PACKET_BUF, 0, (struct sockaddr*)&packet_info, &packet_info_size);
        if (len == -1)
        {
            perror("err: ");
            printf("recvfrom returned -1\n");
            exit(-1);
        }
                
        parse_eth_headers(packet_buffer, PACKET_BUF);
        parse_ip_headers(packet_buffer, PACKET_BUF);
        parse_tcp_headers(packet_buffer, PACKET_BUF);

        // printf("%d\n", is_tcp_ip_packet(packet_buffer, PACKET_BUF));

        if ((is_tcp_ip_packet(packet_buffer, PACKET_BUF)) == 1)
        {
            if (!parse_data(packet_buffer, PACKET_BUF))
                packets_to_sniff++;
        }
    }

    close(sr_fd);

    return 0;
}