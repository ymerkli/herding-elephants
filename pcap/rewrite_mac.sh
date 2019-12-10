#!/bin/bash

#rewrites the srcMAC of the packets in the pcap file to the MAC of the interface on host h1 looking to load balancer lb1
#rewrites the dstMAC of the packets in the pcap file to the MAC of the interface on load balancer lb1 looking to host h1

function usage {
    echo "usage: $0 <input_pcap_file_path> <output_pcap_file_path>"
} 

if [ "$#" -ne 2 ]; then
    usage
    exit
fi

tcprewrite --dlt=enet --enet-smac='00:00:0a:0b:01:02' --enet-dmac='00:01:0a:0b:01:02' --infile=$1 --outfile=$2