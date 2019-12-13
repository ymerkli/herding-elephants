/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


#include "headers_and_structs.p4"
#include "parser.p4"

// Hash table and group table properties
#define HASH_TABLE_FIELD_WIDHT 64
#define ENTRIES_HASH_TABLE_1 100000
#define ENTRIES_HASH_TABLE_2 10000
#define ENTRIES_HASH_TABLE_3 1000

// corresponds to 1/10
#define UINT32_10 429496729


// Does the flow counter lookup for a given hash table.
// IN:  num defining which hash table should be used
// REQ: meta.hash_data.hash_key
// STORED:  found flag (if empty space or flow is found) -> meta.found_flag
//          flow count (if found) -> meta.flow_count
#define HASH_AND_CHECK(num) hash(meta.hash_data.hash_table_entry, HashAlgorithm.crc32_custom, (bit<1>)0, {hdr.ipv4.srcAddr, \
         hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}, (bit<32>)ENTRIES_HASH_TABLE_##num); \
         hash_table_##num.read(meta.hash_data.value, meta.hash_data.hash_table_entry); \
         if (meta.hash_data.value == 0) { \
             meta.found_flag = ##num; \
         } else { \
             meta.hash_data.read_key = (bit<32>) (meta.hash_data.value >> 32); \
             if (meta.hash_data.read_key == meta.hash_data.hash_key) { \
                 meta.flow_count = (bit<32>) meta.hash_data.value & 0x00000000ffffffff; \
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
    register<bit<32>>(1) report_threshold;

    // Used to store report counters for debugging and evaluation.
    register<bit<32>>(1) count_reports;

    // hash tables to store counters
    register<bit<HASH_TABLE_FIELD_WIDHT>>(ENTRIES_HASH_TABLE_1) hash_table_1;
    register<bit<HASH_TABLE_FIELD_WIDHT>>(ENTRIES_HASH_TABLE_2) hash_table_2;
    register<bit<HASH_TABLE_FIELD_WIDHT>>(ENTRIES_HASH_TABLE_3) hash_table_3;

    // used to introduce more randomness in the flip function
    register<bit<32>>(1) last_coinflips;

    // sends a report msg to the local controller with the 5tuple and the current
    // flow counter.
    action sendReport() {
        bit<32> count_report;
        count_reports.read(count_report, 0);
        count_report = count_report + 1;
        count_reports.write(0, count_report);
        clone3(CloneType.I2E, 100, meta);
    }

    // sends an error message, indicated by an all zero 5-tuple to the
    // controller. the flow counter is used to transmit the error code.
    action sendError() {
        meta.tau = INT32_MAX;
        meta.send_count = (bit<32>) error_code;
        clone3(CloneType.I2E, 100, meta);
    }

    // Takes timestamps and ip dst/srcAddr and hashes them to a bit 32 value
    // which is compared against the saved probabilities.
    // REQ: meta.flip_r (report probability)
    //      sampling_probability(0)
    //          report coinflip -> meta.flip_r
    action flip() {
        // report probability is 1/k which is 1/10 with our setup.
        uint32_probability p_report = UINT32_10;
        // load last coin flip values to use them as fields in the new coin flip
        bit<32> last_flip_r;
        last_coinflips.read(last_flip_r, 0);
        // generate hashes
        hash(meta.flip_r, HashAlgorithm.crc32, (bit<1>)0,
            {standard_metadata.enq_timestamp,
                standard_metadata.ingress_global_timestamp,
                hdr.ipv4.srcAddr, last_flip_r}, INT32_MAX);
        // safe hashes
        last_coinflips.write(0, meta.flip_r);
        // compare against the stored probabilities and set the flip fields
        // accordingly.
        if (meta.flip_r < p_report) {
            meta.flip_r = 1;
        } else {
            meta.flip_r = 0;
        }
    }

    apply {

        // Herd section //

        if(hdr.ipv4.isValid()) {

            flip();
            report_threshold.read(meta.tau, 0);

            // reset fields and generate flow id
            meta.found_flag = 0;
            meta.flow_count = 0;
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
                meta.flow_count = meta.flow_count + 1;

                // set the report coinflip to zero if the threshold is not reached
                // reset counter if threshold is reached and
                if (meta.flow_count < meta.tau) {
                    meta.flip_r = 0;
                } else {
                    meta.send_count = meta.flow_count;
                    meta.flow_count = 0;
                }
            }

            // report and reset counter if necessary
            if (meta.flip_r == 1) {
                sendReport();
            }

            // store counter if necessary
            meta.hash_data.value = (bit<64>) meta.hash_data.hash_key;
            meta.hash_data.value =  meta.hash_data.value << 32;
            meta.hash_data.value =  meta.hash_data.value + (bit<64>) meta.flow_count;
            if (meta.found_flag == 1) {
                hash_table_1.write(meta.hash_data.hash_table_entry, meta.hash_data.value);
            }
            if (meta.found_flag == 2) {
                hash_table_2.write(meta.hash_data.hash_table_entry, meta.hash_data.value);
            }
            if (meta.found_flag == 3) {
                hash_table_3.write(meta.hash_data.hash_table_entry, meta.hash_data.value);
            }
            // Other packet processing stuff //
            ipv4_lpm.apply();
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
