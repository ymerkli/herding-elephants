/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


#include "headers_and_structs.p4"
#include "parser.p4"
//TODO (to replicate paper):
// 3) Add support for ipv6 and udp

// Hash table and group table properties
#define HASH_TABLE_FIELD_WIDHT 64
#define ENTRIES_HASH_TABLE_1 250000
#define ENTRIES_HASH_TABLE_2 50000
#define ENTRIES_HASH_TABLE_3 10000

#define GROUP_TABLE_SIZE 2<<16


// Does the flow counter lookup for a given hash table.
// IN:  num defining which hash table should be used
// REQ: meta.hash_data.hash_key
// STORED:  found flag (if empty space or flow is found) -> meta.found_flag
//          flow count (if found) -> meta.data.flow_count
#define HASH_AND_CHECK(num) hash(meta.hash_data.hash_table_entry, HashAlgorithm.crc32_custom, (bit<1>)0, {hdr.ipv4.srcAddr, \
         hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}, (bit<32>)ENTRIES_HASH_TABLE_##num); \
         hash_table_##num.read(meta.hash_data.value, meta.hash_data.hash_table_entry); \
         if (meta.hash_data.value == 0) { \
             meta.found_flag = ##num; \
         } else { \
             meta.hash_data.read_key = (bit<32>) (meta.hash_data.value >> 32); \
             if (meta.hash_data.read_key == meta.hash_data.hash_key) { \
                 meta.data.flow_count = (bit<32>) meta.hash_data.value & 0x00000000ffffffff; \
                 meta.found_flag = ##num; \
             } \
         }


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

    bit<4> error_code;

        action drop() {
        mark_to_drop(standard_metadata);
    }

    action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops){
        hash(meta.ecmp_hash,
	    HashAlgorithm.crc16,
	    (bit<1>)0,
	    { hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol},
	    num_nhops);

	    meta.ecmp_group_id = ecmp_group_id;
    }

    action set_nhop(macAddr_t dstAddr, egressSpec_t port) {

        //set the src mac address as the previous dst, this is not correct right?
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ecmp_group_to_nhop {
        key = {
            meta.ecmp_group_id:    exact;
            meta.ecmp_hash: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 1024;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            ecmp_group;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    // extracts the five tuple identifying a flow from the packet
    action extractFiveTuple() {
        meta.data.five_tuple.srcAddr = hdr.ipv4.srcAddr;
        meta.data.five_tuple.dstAddr = hdr.ipv4.dstAddr;
        meta.data.five_tuple.srcPort = hdr.tcp.srcPort;
        meta.data.five_tuple.dstPort = hdr.tcp.dstPort;
        meta.data.five_tuple.protocol = hdr.ipv4.protocol;
    }

    action extractGroup() {
        meta.group.srcGroup = (bit<8>) (hdr.ipv4.srcAddr & 0xff000000 >> 24);
        meta.group.dstGroup = (bit<8>) (hdr.ipv4.dstAddr & 0xff000000 >> 24);
        }

    // Hashes the 5-tuple to generate an id
    // STORED: hash_key -> meta.hash_data.hash_key
    action hashFlow() {
        hash(meta.hash_data.hash_key, HashAlgorithm.crc32, (bit<1>)0,
            {hdr.ipv4.srcAddr,
             hdr.ipv4.dstAddr,
             hdr.tcp.srcPort,
             hdr.tcp.dstPort,
             hdr.ipv4.protocol},(bit<32>) INT32_MAX);
    }


        ///               HERD SECTION                  ///

    // registers set by local controller
    register<bit<32>>(1) sampling_probability;
    register<bit<32>>(1) count_start; // equals 1/sampling_probability

    // hash tables to store counters
    register<bit<HASH_TABLE_FIELD_WIDHT>>(ENTRIES_HASH_TABLE_1) hash_table_1;
    register<bit<HASH_TABLE_FIELD_WIDHT>>(ENTRIES_HASH_TABLE_2) hash_table_2;
    register<bit<HASH_TABLE_FIELD_WIDHT>>(ENTRIES_HASH_TABLE_3) hash_table_3;

    // used to introduce more randomness in the flip function
    register<bit<32>>(2) last_coinflips;

    // sends a hello msg to the local controller with the 5tuple and a flow
    // counter of 0 to indicate the flow is new.
    action sendHello() {
        extractFiveTuple();
        meta.data.flow_count = 0;
        digest(1, meta.data);
    }

    // sends a report msg to the local controller with the 5tuple and the current
    // flow counter.
    action sendReport() {
        extractFiveTuple();
        digest(1, meta.data);
    }

    // sends an error message, indicated by an all zero 5-tuple to the
    // controller. the flow counter is used to transmit the error code.
    action sendError() {
        meta.data.five_tuple.srcAddr = 0;
        meta.data.five_tuple.dstAddr = 0;
        meta.data.five_tuple.srcPort = 0;
        meta.data.five_tuple.dstPort = 0;
        meta.data.five_tuple.protocol = 0;
        meta.data.flow_count = (bit<32>) error_code;
        digest(1, meta.data);
    }

    // called by a table hit in group_table
    // IN:  group report probability (converted to uint32) p_report,
    //      group parameter tau (threshold)
    // STORED:  group threshold -> meta.tau
    //          report probability -> meta.flip_r
    action getValues(uint32_probability p_report, tau_t tau_g) {
        meta.tau = tau_g;
        meta.flip_r = p_report;
    }

    // Takes timestamps and ip dst/srcAddr and hashes them to a bit 32 value
    // which is compared against the saved probabilities.
    // REQ: meta.flip_r (report probability)
    //      sampling_probability(0)
    // STORED:  sampling coinflip -> meta.flip_s
    //          report coinflip -> meta.flip_r
    action flip() {
        uint32_probability p_report = meta.flip_r;
        uint32_probability p_sample;
        // load last coin flip values to use them as fields in the new coin flip
        bit<32> last_flip_s;
        bit<32> last_flip_r;
        last_coinflips.read(last_flip_s, 0);
        last_coinflips.read(last_flip_r, 1);
        sampling_probability.read(p_sample, 0);
        // generate hashes
        hash(meta.flip_s, HashAlgorithm.crc32, (bit<1>)0,
            {standard_metadata.enq_timestamp,
                standard_metadata.ingress_global_timestamp,
                hdr.ipv4.dstAddr, last_flip_r}, INT32_MAX);
        hash(meta.flip_r, HashAlgorithm.crc32, (bit<1>)0,
            {standard_metadata.enq_timestamp,
                standard_metadata.ingress_global_timestamp,
                hdr.ipv4.srcAddr, last_flip_s}, INT32_MAX);
        // safe hashes
        last_coinflips.write(0, meta.flip_s);
        last_coinflips.write(1, meta.flip_r);
        // compare against the stored probabilities and set the flip fields
        // accordingly.
        if (meta.flip_s < p_sample) {
            meta.flip_s = 1;
        } else {
            meta.flip_s = 0;
        }
        if (meta.flip_r < p_report) {
            meta.flip_r = 1;
        } else {
            meta.flip_r = 0;
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

        if(hdr.ipv4.isValid()) {
            // extract the first 8 bits of the ip addresses to use in the
            // group_values table lookup
            extractGroup();
            // if we have an entry hit, we get the group parameters and can proceed
            if (group_values.apply().hit) {
                // simulate coin flips (meta.flip_r is now set)
                flip();

                // reset fields and generate flow id
                meta.found_flag = 0;
                meta.data.flow_count = 0;
                hashFlow();

                // search for a stored value
                HASH_AND_CHECK(1)
                if (meta.found_flag == 0) {
                    HASH_AND_CHECK(2);
                }
                if (meta.found_flag == 0) {
                    HASH_AND_CHECK(3);
                }

                // send error if no space and value found
                if (meta.found_flag == 0) {
                    meta.flip_r = 0;
                    error_code = 0x0;
                    sendError();
                } else {
                    // check if we found an empty space, if so, try to sample
                    if (meta.hash_data.value == 0) {
                        if (meta.flip_s == 1) {
                            count_start.read(meta.data.flow_count, 0);
                        }
                    // increase counter
                    } else {
                        meta.data.flow_count = meta.data.flow_count + 1;
                    }
                    // set the report coinflip to zero if the threshold is not reached
                    if (meta.data.flow_count < meta.tau) {
                        meta.flip_r = 0;
                    }
                }

                // report and reset counter if necessary
                if (meta.flip_r == 1) {
                    sendReport();
                    meta.data.flow_count = 0;
                }

                // store counter if necessary
                if (meta.data.flow_count > 0 || meta.flip_r == 1) {
                    meta.hash_data.value = (bit<64>) meta.hash_data.hash_key;
                    meta.hash_data.value =  meta.hash_data.value << 32;
                    meta.hash_data.value =  meta.hash_data.value + (bit<64>) meta.data.flow_count;
                    if (meta.found_flag == 1) {
                        hash_table_1.write(meta.hash_data.hash_table_entry, meta.hash_data.value);
                    }
                    if (meta.found_flag == 2) {
                        hash_table_2.write(meta.hash_data.hash_table_entry, meta.hash_data.value);
                    }
                    if (meta.found_flag == 3) {
                        hash_table_3.write(meta.hash_data.hash_table_entry, meta.hash_data.value);
                    }
                }
            // no group_values table hit -> send hello message to controller
            } else {
                sendHello();
            }
        }


                // Other packet processing stuff //


        if (hdr.ipv4.isValid()){
            switch (ipv4_lpm.apply().action_run){
                ecmp_group: {
                    ecmp_group_to_nhop.apply();
                }
            }
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
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
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
