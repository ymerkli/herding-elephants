/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


#include "headers_and_structs.p4"
#include "parser.p4"

#define UINT32_95 4080218930

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {

     }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<9>>(1) host_port;
    register<bit<48>>(1) host_mac;

    action drop() {
        mark_to_drop(standard_metadata);
    }


    apply {

        if (hdr.ipv4.isValid()) {
            host_port.read(standard_metadata.egress_spec, 0);
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            host_mac.read(hdr.ethernet.dstAddr, 0);
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        } else {
            drop();
        }

     }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {

     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
    	      hdr.ipv4.isValid(),
                { hdr.ipv4.version,
    	            hdr.ipv4.ihl,
                  hdr.ipv4.dscp,
                  hdr.ipv4.ecn,
                  hdr.ipv4.totalLen,
                  hdr.ipv4.identification,
                  hdr.ipv4.flags,
                  hdr.ipv4.fragOffset,
                  hdr.ipv4.ttl,
                  hdr.ipv4.protocol,
                  hdr.ipv4.srcAddr,
                  hdr.ipv4.dstAddr },
                  hdr.ipv4.hdrChecksum,
                  HashAlgorithm.csum16);
        }
    }

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
