from scapy.all import *

def main():
    pcap_path = "Ethernet_test_pcap.pcap"
    pkts = rdpcap(pcap_path)

    for pkt in pkts:
        protocol = 0

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = pkt[IP].proto
            src_port = pkt[IP].sport
            dst_port = pkt[IP].dport

            print("##### ")
            print("##### IP: from [{}] --> to [{}]".format(src_ip, dst_ip))
            if protocol == 6:
                print("##### TCP: from [{}] --> to [{}]".format(src_port, dst_port))
            elif protocol == 17:
                print("##### UDP: from [{}] --> to [{}]".format(src_port, dst_port))
        '''
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            # IPv6 doens't have protocol
            src_port = pkt[IPv6].sport
            dst_port = pkt[IPv6].dport

            print("##### ")
            print("##### IP: from [{}] --> to [{}]".format(src_ip, dst_ip))
            print("##### Ports: from [{}] --> to [{}]".format(src_port, dst_port))
        '''

        if Ether in pkt:
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst

            print("##### MAC: from [{}] --> to [{}]".format(src_mac, dst_mac))


if __name__ == '__main__':
    main()
