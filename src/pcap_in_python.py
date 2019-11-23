from scapy.all import *

# TODO: try Ether(src=get_if_hwaddr(interface)) somehow

def main():
    pcap_path = "first500.pcap"
    pkts = rdpcap(pcap_path)

    mac_available = 0
    for pkt in pkts:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = pkt[IP].proto
            src_port = pkt[IP].sport
            dst_port = pkt[IP].dport
            # There seems to be no Ethernet traffic recorded in the CAIDA file
            try:
                # prints this PC's MAC
                src_mac = Ether().src
                dst_mac = Ether().dst
                mac_available = 1
            except:
                pass

            print("##### IP: from [{}] --> to [{}]".format(src_ip, dst_ip))
            if mac_available == 1:
                print("##### MAC: from [{}] --> to [{}]".format(src_mac, dst_mac))
            if protocol == 6:
                # print("##### TCP")
                print("##### TCP: from [{}] --> to [{}]".format(src_port, dst_port))
            elif protocol == 17:
                # print("##### UDP")
                print("##### UDP: from [{}] --> to [{}]".format(src_port, dst_port))

    print("test : {}".format(pkt[IP].src))


if __name__ == '__main__':
    main()
