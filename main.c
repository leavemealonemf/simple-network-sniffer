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
    printf("\n");
    printf("%s", msg);

    while (len--)
    {
        printf("%.2X ", *p);
        p++;
    }
}

void print_packet_info_hex(unsigned char *packet, int packet_size)
{   
    unsigned char *p = packet;
    printf("\n\n---------packet--start-----------\n\n");

    while(packet_size--)
    {
        printf("%.2x ", *p);
        p++;
    }

    printf("\n\n---------packet--end-----------\n\n");
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
    
    printf("-----------------------");
    print_in_hex(" - Destination MAC Addr: ", eth_header->h_dest, 6);
    print_in_hex(" - Source MAC Addr: ", eth_header->h_source, 6);
    print_in_hex(" - Protocol: ", (unsigned char*)&eth_header->h_proto, 2);
}

void parse_ip_headers(unsigned char *packet, int packet_size)
{
    struct ethhdr* eth_header;
    struct iphdr* ip_header;

    eth_header = (struct ethhdr*)packet;

    uint16_t ip_p = 2048;

    if (ntohs(eth_header->h_proto) == ip_p)
    {
        if (packet_size >= (sizeof(struct ethhdr) + sizeof(struct iphdr)))
        {
            ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));

            struct in_addr d_addr, s_addr;
            d_addr.s_addr = ip_header->daddr;
            s_addr.s_addr = ip_header->saddr;

            printf("\n - Desctination IP Addr: %s", inet_ntoa(d_addr));
            printf("\n - Source IP Addr: %s\n", inet_ntoa(s_addr));
        } else 
            printf("\n - Desctination IP Addr: NULL\n");
        
    }
    printf("\n");
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        printf("Run failed. Exec commad: ./a.out <network interface> <packet's count>\n");
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
                
        // print_packet_info_hex(packet_buffer, PACKET_BUF);
        parse_eth_headers(packet_buffer, PACKET_BUF);
        parse_ip_headers(packet_buffer, PACKET_BUF);
    }

    close(sr_fd);

    return 0;
}