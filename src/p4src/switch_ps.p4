/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


#include "headers_and_structs.p4"
#include "parser.p4"

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

    ///         GENERAL PACKET PROCESSING STUFF        ///

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_nhop(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            drop;
        }
        size = 256;
        default_action = drop;
    }


        ///               HERD SECTION                  ///

    // registers set by local controller
    register<bit<32>>(1) sampling_probability;
    register<bit<32>>(1) count_start; // equals 1/sampling_probability

    register<bit<32>>(1) count_reports;


    // used to introduce more randomness in the flip function
    register<bit<32>>(2) last_coinflips;


    // sends a report msg to the local controller with the 5tuple and the current
    // flow counter.
    action sendReport() {
        bit<32> count_report;
        count_reports.read(count_report, 0);
        count_report = count_report + 1;
        count_reports.write(0, count_report);
        clone3(CloneType.I2E, 100, meta);
    }



    // Takes timestamps and ip dst/srcAddr and hashes them to a bit 32 value
    // which is compared against the saved probabilities.
    // REQ: meta.flip_r (report probability)
    //      sampling_probability(0)
    // STORED:  sampling coinflip -> meta.flip_s
    //          report coinflip -> meta.flip_r
    action flip() {
        uint32_probability p_sample;
        // load last coin flip values to use them as fields in the new coin flip
        bit<32> last_flip_s;
        last_coinflips.read(last_flip_s, 0);
        sampling_probability.read(p_sample, 0);
        // generate hashes
        hash(meta.flip_s, HashAlgorithm.crc32, (bit<1>)0,
            {standard_metadata.enq_timestamp,
                standard_metadata.ingress_global_timestamp,
                hdr.ipv4.dstAddr, last_flip_s}, INT32_MAX);
        // safe hashes
        last_coinflips.write(0, meta.flip_s);
        // compare against the stored probabilities and set the flip fields
        // accordingly.
        if (meta.flip_s < p_sample) {
            meta.flip_s = 1;
        } else {
            meta.flip_s = 0;
        }
    }

    // group id MAT to retrieve the group parameters (local probability
    // and local threshold). a hit calls the getValues action which writes them
    // in the metadata
    table group_values {
        key = {
            meta.group.srcGroup: exact;
            meta.group.dstGroup: exact;
        }
        actions = {
            getValues;
            NoAction;
        }
        size = GROUP_TABLE_SIZE;
        default_action = NoAction;
    }

    apply {

        // Herd section //

        // simulate coin flips (meta.flip_r is now set)
        flip();

        // try to sample and send report.
        if (meta.flip_s == 1) {
            meta.send_count = 1;
            sendReport();
        }

        // Other packet processing stuff //
        ipv4_lpm.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.instance_type == 1){
            hdr.cpu.setValid();
            if(meta.tau == INT32_MAX){
                hdr.cpu.srcAddr  = 0;
                hdr.cpu.dstAddr  = 0;
                hdr.cpu.srcPort  = 0;
                hdr.cpu.dstPort  = 0;
                hdr.cpu.protocol = 0;
            } else {
                hdr.cpu.srcAddr  = hdr.ipv4.srcAddr;
                hdr.cpu.dstAddr  = hdr.ipv4.dstAddr;
                hdr.cpu.srcPort  = hdr.tcp.srcPort;
                hdr.cpu.dstPort  = hdr.tcp.dstPort;
                hdr.cpu.protocol = hdr.ipv4.protocol;
            }
            hdr.cpu.flow_count = meta.send_count;
            hdr.ethernet.etherType = CLONE_ETHER_TYPE;

            hdr.ipv4.setInvalid();
            hdr.tcp.setInvalid();
            bit<32> new_length = CPU_HEADER_BYTE_LENGTH + ETHERNET_HEADER_BYTE_LENGTH;
            truncate(new_length);
        }
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
