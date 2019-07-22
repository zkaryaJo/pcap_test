#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#pragma warning(disable : 4691)


typedef struct eHeader //14byte
{
    u_char dMac[6];     //6byte
    u_char sMac[6];     //6byte
    u_char type[2];     //2byte

} eHeader;

typedef struct ipHeader{ //14+20byte
    u_char ethernet_header[14];     //14byte
    u_char version_headerLength;    //1byte
    u_char typeofService;           //1byte
    u_char totalLength[2];          //2byte
    u_char Identifier[2];           //2byte
    u_char flags_fragmentOffset[2]; //2byte
    u_char ttl;                     //1byte
    u_char protocol;                //1byte
    u_char checkSum[2];             //2byte
    u_char sIP[4];                  //4byte
    u_char dIP[4];                  //4byte

} ipHeader;

typedef struct tcpHeader{   //34+20byte
    u_char ethernet_ip_header[34];
    u_char sPort[2];        // 2byte
    u_char dPort[2];        // 2byte
    u_char seqNumber[4];    // 4byte
    u_char ackNumber[4];    // 4byte
    u_char offset_reserved; // 1byte
    u_char tcpFlag;         // 1byte
    u_char windows[2];      // 2byte
    u_char checkSum[2];     // 2byte
    u_char urgentPointer[2]; //2byte

} tcpHeader;

typedef struct httpHeader{
    u_char tcp_header[54];
    u_char data[1000];

} httpHeader;

void usage() {
  printf("syntax: pcap_test <interface>\n");   printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

  if (handle == NULL) { // handle Null
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    eHeader *eheader = (eHeader*)packet;

    if(eheader->type[0]==0x08 && eheader->type[1]==0x00){ //ip = 0x0800

        ipHeader *ipheader = (ipHeader*)packet;

        if(ipheader->protocol == 0x06){ // tcp =0x06

            tcpHeader *tcpheader = (tcpHeader*)packet;

            if((tcpheader->sPort[0] == 0x00 && tcpheader->sPort[1] ==0x50) ||
                    (tcpheader->dPort[0] == 0x00 && tcpheader->dPort[1] ==0x50))  { //http = 0x0050

                httpHeader *httpheader = (httpHeader*)packet;

                for(int i=0;i<(int)header->len;i++){
                    //printf("%d : %02X    ",i, httpheader->data[i]);
                    if((httpheader->data[i]==0x0d)&&(httpheader->data[i+1]==0x0a)
                            && (httpheader->data[i+2]==0x0d) && (httpheader->data[i+3]==0x0a)){
                        int index = i+4;
                        if(httpheader->data[index] != 0x00 && httpheader->data[index+1]!=0x00
                                && httpheader->data[index+2]!=0x00 && httpheader->data[index+3]!=0x00) {

                            printf("\n type: "); for(int j=0;j<2;j++) printf("%02X ", eheader->type[j]);      // type
                            printf("\n dMac: "); for(int j=0;j<6;j++) printf("%02X ", eheader->dMac[j]);      // Destination-Mac
                            printf("\n sMac: "); for(int j=0;j<6;j++) printf("%02X ", eheader->sMac[j]);      // Source-Mac

                            printf("\n protocol: ");                  printf("%d ", ipheader->protocol);       // protocol
                            printf("\n sIP: ");      for(int j=0;j<4;j++) printf("%d.", ipheader->sIP[j]);     // source-IP
                            printf("\n dIP: ");      for(int j=0;j<4;j++) printf("%d.", ipheader->dIP[j]);     // destination-IP

                            printf("\n sPort: "); printf("%02d ", ((tcpheader->sPort[0])<<8|tcpheader->sPort[1]));  // S-port
                            printf("\n dPort: "); printf("%02d ", (tcpheader->dPort[0]<<8|tcpheader->sPort[1]));    // d-port
                            printf("\n Data : ");

                            for(int j=0;j<10;j++) printf("%02X ", httpheader->data[index+j]); // Data
                            printf("\n\n");
                            break;
                        }
                    }
                }

            }
        }
    }

    //printf("\n %u bytes captured\n", header->caplen);
  }

  pcap_close(handle);
  return 0;
}
