#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void usage() {
    printf("syntax: ./pcap-test <interface>\n");
    printf("sample: ./pcap-test dum0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

typedef struct ether_header {
    uint8_t dest_mac[6];  // 도착 MAC 주소
    uint8_t src_mac[6];   // 소스 MAC 주소
    uint16_t eth_type;   // 이더넷 타입 (2 바이트)
} ether_header; 

typedef struct ip_header {
    uint8_t ver_ihl;      // 버전 및 IHL 1
        
    uint8_t protocol;     // 프로토콜  1 
      
    uint8_t ip_src[4];    // 소스 IP 주소  4
    uint8_t ip_dst[4];    // 목적지 IP 주소 4 
} ip_header;

typedef struct tcp_header {
    uint16_t src_port;    // 소스 포트 2
    uint16_t dst_port;    // 목적지 포트 2
    
    uint8_t offset_res;   // 데이터 오프셋(상위 4비트) 및 예약(하위 4비트)   1
   


} tcp_header;

void print_mac_address(uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        printf("%x", mac[i]);
        if (i < 5) printf(":");
    }
}

void print_ip_address(uint8_t* ip) {
    for (int i = 0; i < 4; i++) {
        printf("%d", ip[i]);
        if (i < 3) printf(".");
    }
}

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // 이더넷 헤더 처리
        ether_header eh;
        for (int i = 0; i < 6; i++) {
            eh.dest_mac[i] = packet[i];
            eh.src_mac[i] = packet[6 + i];
        }
        eh.eth_type = (packet[12] << 8) | packet[13];

        
        
        if(eh.eth_type != 0x0800 ){
            continue;
        };


        // IP 헤더 처리

        int ip_header_offset = 14; // ip 헤더의 시작 주소 
        ip_header ih;
        ih.ver_ihl = packet[ip_header_offset];

         // IHL 바이트에서 45 일때  상위  4비트는 4  버전을 의미 하위 4 비트는  길이(20)를 4 로 나눈 값  
         // 따라서 하위 4 비트로 부터 나온 5 에다가 4 를 곱하여 ip 헤더길이를 역 연산 

        int ip_header_length = (ih.ver_ihl & 0x0F) * 4;

         // TCP 패킷인지 아닌지 그 다음에 올 번호는 인덱스 기준 9 번에 있음 
         // tcp 면 6 임 
        ih.protocol = packet[ip_header_offset + 9];

        // IP 주소 추출
        // 각각 ip 헤더의 인덱스 기준 12 부터 15  , 16 부터 19  
        for (int i = 0; i < 4; i++) {
            ih.ip_src[i] = packet[ip_header_offset + 12 + i];
            ih.ip_dst[i] = packet[ip_header_offset + 16 + i];
        }

       
        if (ih.protocol != 6) {
            continue; // ip 의 다음에 오는 헤더가 TCP인 패킷이 아니면 pass ㄱㄱ 
        }

        // TCP 헤더 처리
        int tcp_header_offset = ip_header_offset + ip_header_length;   // 예시 14(고정) + 20 (변동 될 수 있음 ) 

        tcp_header th;
        
        // TCP 포트 정보 (빅 엔디안 -> 호스트 엔디안)
        th.src_port = (packet[tcp_header_offset] << 8) | packet[tcp_header_offset + 1];

        th.dst_port = (packet[tcp_header_offset + 2] << 8) | packet[tcp_header_offset + 3];
        
        // 데이터 오프셋 (TCP 헤더 길이)   a0 즉 1010 0000
        // 인덱스 기준 12 번 뒤에 있다 그리고 
        // 상위 4비트가 주소를 4 로나눈 값이고 하위는 예약된 비트(?)라고한다 왜 있는지는 모르겠다 
        th.offset_res = packet[tcp_header_offset + 12];
        

        // 아무튼 상위 비트로 부터 4를 곱해서 tcp 길이도 구하자  예시 10 * 4 = 40 바이트 
        int tcp_header_length = (th.offset_res >> 4) * 4; // 상위 4비트에 4를 곱함
        
        // 결과 출력
     //   printf("Ethernet: ");
        print_mac_address(eh.src_mac);
        printf(" -> ");
        print_mac_address(eh.dest_mac);
        printf(", ");
        
     //   printf("IP: ");
        print_ip_address(ih.ip_src);
        printf(" -> ");
        print_ip_address(ih.ip_dst);
        printf(", ");
        
        printf("%d -> %d\n", th.src_port, th.dst_port);
        
        // 페이로드 처리
        int payload_offset = tcp_header_offset + tcp_header_length;

        // 패킷의 끝 위치에서 페이로드 시작주소를 빼서 크기를 구한다  
        int payload_length = header->caplen - payload_offset;
        
        if (payload_length > 0) {
            // 최대 20바이트까지만 출력
            int max_payload_length = (payload_length < 20) ? payload_length : 20;

            for (int i = 0; i < max_payload_length; i++) {

                printf("%x", packet[payload_offset + i]);
                if(i!=max_payload_length-1){
                    printf("|");
                }
                
            }
            printf("\n");
        } else {
            printf("-\n");
        }
        
        printf("\n"); // 패킷 간 구분을 위한 빈 줄
    }

    pcap_close(pcap);
    return 0;
}