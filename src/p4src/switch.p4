/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//TODO (to replicate paper):
// 3) Add support for ipv6 and udp

// Typedefs //
// Used for threshold variables
typedef bit<32> tau_t;
// Probabilities converted as: u_p = 2^32*p - 1, p in (0,1)
typedef bit<32> uint32_probability;
// Used for hashes of a flow five tuple
typedef bit<32> flow_id_t;
typedef bit<8> error_code_t;

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// Constants //
const uint32_probability INT32_MAX = 4294967295;

const bit<16> ipv4_type = 0x800;


#define HASH_TABLE_FIELD_WIDHT 64
#define ENTRIES_HASH_TABLE_1 1000
#define ENTRIES_HASH_TABLE_2 100
#define ENTRIES_HASH_TABLE_3 10

#define GROUP_TABLE_SIZE 1000


#define HASH_AND_CHECK(num) hash(meta.hash_data.hash_value, HashAlgorithm.crc32_custom, (bit<1>)0, {hdr.ipv4.srcAddr, \
         hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}, (bit<32>)ENTRIES_HASH_TABLE_##num); \
         hash_table_##num.read(meta.hash_data.read_value, meta.hash_data.hash_value); \
         if (meta.hash_data.read_value == 0) { \
             meta.found_flag = ##num; \
         } else { \
             meta.hash_data.read_key = (bit<32>) (meta.hash_data.read_value >> 32); \
             if (meta.hash_data.read_key == meta.hash_data.hash_key) { \
                 meta.data.flow_count = (bit<32>) meta.hash_data.read_value & 0x00000000ffffffff; \
                 meta.found_flag = ##num; \
             } \
         }


/*************************************************************************
*********************** S T R U C T S  ***********************************
*************************************************************************/

struct five_tuple_t {
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<8>    protocol;
}

// Used by the digest commands to transport data to the local controller
struct report_data_t {
    five_tuple_t five_tuple;
    bit<32> flow_count;
}

struct report_error_t {
    error_code_t data;
}

struct hash_data_t {
    bit<32> hash_key;
    bit<32> hash_value;
    bit<64> read_value;
    bit<32> read_key;
}

struct flow_group_t {
    bit<8> srcGroup;
    bit<8> dstGroup;
}



// We need fields for: 2 coinflips,
//                     1 local threshold,
//                     1 five-tuple hash,
//                     1 struct for digest command
struct metadata {
    uint32_probability flip_s;
    uint32_probability flip_r;
    tau_t tau;
    flow_id_t flow_id;
    report_data_t data;
    hash_data_t hash_data;
    bit<2> found_flag;
    flow_group_t group;
}


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            ipv4_type: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6 : parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
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
    report_error_t error_code;

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

    // Hashes the ip.src+dstAddr, ip.protocol and tcp.src+dstAddr to generate a
    // flow id for register lookup
    // OUT: writes result to meta.flow_id
    action hashFlow() {
        hash(meta.hash_data.hash_key, HashAlgorithm.crc32, (bit<1>)0,
            {hdr.ipv4.srcAddr,
             hdr.ipv4.dstAddr,
             hdr.tcp.srcPort,
             hdr.tcp.dstPort,
             hdr.ipv4.protocol},(bit<32>) INT32_MAX);
    }


        ///               HERD SECTION                  ///

    register<bit<32>>(1) sampling_probability;
    register<bit<32>>(1) count_start; // equals 1/sampling_probability

    register<bit<HASH_TABLE_FIELD_WIDHT>>(ENTRIES_HASH_TABLE_1) hash_table_1;
    register<bit<HASH_TABLE_FIELD_WIDHT>>(ENTRIES_HASH_TABLE_2) hash_table_2;
    register<bit<HASH_TABLE_FIELD_WIDHT>>(ENTRIES_HASH_TABLE_3) hash_table_3;

    // sends a hello msg to the local controller with the 5tuple and a flow
    // counter of 0 to indicate the flow is new.
    action sendHello() {
        extractFiveTuple();
        meta.data.flow_count = 0;
        digest(1, meta.data);
    }

    // send a report msg to the local controller with the 5tuple and the current
    // flow counter.
    action sendReport() {
        extractFiveTuple();
        digest(1, meta.data);
    }
    action sendTableError() {
        error_code.data = 0x00;
        digest(1, error_code.data);
    }

    // called by a table hit in group_table
    // IN:  group report probability (converted to uint32) p_report,
    //      group parameter tau (threshold)
    // OUT: Safes the given parameters in meta.tau and meta.flip_r
    action getValues(uint32_probability p_report, tau_t tau_g) {
        meta.tau = tau_g;
        meta.flip_r = p_report;
    }


    //TODO: introduce more randomness
    //      IDEA: Hash with some RndVal safed in a register
    // Takes timestamps and ip dst/srcAddr and hashes them to a bit 32 value
    // which is compared against the saved probabilities.
    // OUT: writes the outcome to the meta.flip_r and meta.flip_s fields of the
    //      packet
    action flip() {
        uint32_probability p_report = meta.flip_r;
        uint32_probability p_sample;
        sampling_probability.read(p_sample, 0);
        hash(meta.flip_s, HashAlgorithm.crc32, (bit<1>)0,
            {standard_metadata.enq_timestamp,
                standard_metadata.ingress_global_timestamp,
                hdr.ipv4.dstAddr}, INT32_MAX);
        hash(meta.flip_r, HashAlgorithm.crc32, (bit<1>)0,
            {standard_metadata.enq_timestamp,
                standard_metadata.ingress_global_timestamp,
                hdr.ipv4.srcAddr}, INT32_MAX);
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
    //TODO: better idea for keys?
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

    /*

    // Does the value lookup of a the meta.flow_id field in the key value
    // storage reg_counters (which is a single register atm) and updates it
    // with the new value (either +1 or reset to 0). Sets the
    // meta.flip_r field to 0 if the criteria of a report are not met (No
    // change otherwise).
    // If no value is found, a counter is started if the meta.flip_1 field is
    // equal to 1.
    action updateAndCheckLegacy() {
        hashFlow();
        bit<16> flow_count;
        reg_counters.read(flow_count, meta.flow_id);
        // if we found a counter, proceed, else try to sample it
        if (flow_count > 0) {
            // if counter is over the threshold, reset and leave meta.flip_r as
            // is, else increment and set it to false
            flow_count = flow_count + 1;
            if (flow_count >= meta.tau) {
                meta.data.flow_count = flow_count;
                flow_count = 0;
            } else {
                meta.flip_r = 0;
            }
        } else {
            // set meta.flip_r to false since we don’t want to report
            meta.flip_r = 0;
            if (meta.flip_s == 1) {
                flow_count = counter_start;
            }
        }
        // write back adapted flow count
        reg_counters.write(meta.flow_id, flow_count);
    }

    */


    apply {

        // Herd section //

        if(hdr.ipv4.isValid()) {
            extractGroup();
            // if we have an entry hit, we get the group parameters and can proceed
            if (group_values.apply().hit) {
                // simulate coin flips
                flip();

                // reset fields and get hash key
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
                    sendTableError();
                } else {
                    // check if we found an empty space, if so, try to sample
                    if (meta.data.flow_count == 0) {
                        if (meta.flip_s == 1) {
                            count_start.read(meta.data.flow_count, 0);
                        }
                    // increase counter and check if we have to report
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

                // store counter
                if (meta.data.flow_count > 0) {
                    meta.hash_data.read_value = (bit<64>) meta.hash_data.hash_key;
                    meta.hash_data.read_value =  meta.hash_data.read_value << 32;
                    meta.hash_data.read_value =  meta.hash_data.read_value + (bit<64>) meta.data.flow_count;
                    if (meta.found_flag == 1) {
                    hash_table_1.write(meta.hash_data.hash_value, meta.hash_data.read_value);
                    }
                    if (meta.found_flag == 2) {
                    hash_table_2.write(meta.hash_data.hash_value, meta.hash_data.read_value);
                    }
                    if (meta.found_flag == 3) {
                    hash_table_3.write(meta.hash_data.hash_value, meta.hash_data.read_value);
                    }
                }

            } else {
                sendHello();
            }
        }

        // Other packet processing stuff //

                   /* empty */
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
        // Packets aren’t changed (yet), nothing to do here
     }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.tcp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ethernet);
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
