/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// Typedefs //
typedef bit<16> tau_t;
typedef bit<32> uint32_probability;
typedef bit<32> flow_id_t;

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// Constants //
const uint32_probability INT32_MAX = 4294967295;

const bit<16> ipv4_type = 0x800;

//TODO: adapt group table size
// there are 2^16 possible group pairs (8bit scr and 8bit dst)
const bit<16> GROUP_TABLE_SIZE = 1000;
//TODO: make these writable at launch
// equals 2^30 or s = 0.25, which is way too high for testing purposes
const uint32_probability SAMPLING_PROBABILITY = 1073741824;
// 1/s such that we know where to start counting
const bit<16> counter_start = 4;
// equals 2^32 or r = 1, for testing purposes
const bit<32> REPORTING_PROBABILITY = 4294967295;

//TODO: add custom hash functions
//TODO: add real key value storage D
#define COUNTERS 1000
#define COUNTER_BIT_WIDTH 16



/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
struct five_tuple_t {
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<8>    protocol;
}

struct report_data_t {
    five_tuple_t five_tuple;
    bit<16> flow_count;
}

struct metadata {
    uint32_probability flip_s;
    uint32_probability flip_r;
    tau_t tau;
    flow_id_t flow_id;
    report_data_t data;
}

//TODO: add ipv6 and udp headers


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

// TODO: change to header union when ipv6 and udp are added
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

//TODO: add states for ipv6 and udp; maybe change default and check for validity
//      in ingress apply.
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

    register<bit<COUNTER_BIT_WIDTH>>(COUNTERS) reg_counters;

    // extracts the five tuple identifying a flow from the packet
    action extractFiveTuple() {
        meta.data.five_tuple.srcAddr = hdr.ipv4.srcAddr;
        meta.data.five_tuple.dstAddr = hdr.ipv4.dstAddr;
        meta.data.five_tuple.srcPort = hdr.tcp.srcPort;
        meta.data.five_tuple.dstPort = hdr.tcp.dstPort;
        meta.data.five_tuple.protocol = hdr.ipv4.protocol;
    }

    action sendHello() {
        extractFiveTuple();
        meta.data.flow_count = 0;
        digest(1, meta.data);

        // TODO: remove, for testing purposes
        standard_metadata.egress_spec = 4;
    }

    action sendReport() {
        extractFiveTuple();
        digest(1, meta.data);

                // TODO: remove, for testing purposes
        standard_metadata.egress_spec = 3;
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
        uint32_probability safe_p_report = meta.flip_r;
        hash(meta.flip_s, HashAlgorithm.crc32, (bit<1>)0,
            {standard_metadata.enq_timestamp,
                standard_metadata.ingress_global_timestamp,
                hdr.ipv4.dstAddr}, INT32_MAX);
        hash(meta.flip_r, HashAlgorithm.crc32, (bit<1>)0,
            {standard_metadata.enq_timestamp,
                standard_metadata.ingress_global_timestamp,
                hdr.ipv4.srcAddr}, INT32_MAX);
        if (meta.flip_s < SAMPLING_PROBABILITY) {
            meta.flip_s = 1;
        } else {
            meta.flip_s = 0;
        }
        //TODO: change to safe_p_report
        if (meta.flip_r < REPORTING_PROBABILITY) {
            meta.flip_r = 1;
        } else {
            meta.flip_r = 0;
        }
    }

    // Hashes the ip.src+dstAddr, ip.protocol and tcp.src+dstAddr to generate a
    // flow id for register lookup
    // OUT: writes result to meta.flow_id

    action hashFlow() {
        hash(meta.flow_id, HashAlgorithm.crc32, (bit<1>)0,
            {hdr.ipv4.srcAddr,
             hdr.ipv4.dstAddr,
             hdr.tcp.srcPort,
             hdr.tcp.dstPort,
             hdr.ipv4.protocol},(bit<16>) COUNTER_BIT_WIDTH);
    }

    // group id MAT to retrieve the group parameters
    //TODO: fix keys
    table groups {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            getValues;
            NoAction;
        }
        size = GROUP_TABLE_SIZE;
        default_action = NoAction;
    }

    // Does the value lookup of a flow. If no value is found, we try to sample.
    action updateAndCheck() {
        //TODO: implement real hash table lookup
        hashFlow();
        bit<16> flow_count;
        reg_counters.read(flow_count, meta.flow_id);
        // if we found a counter, proceed, else try to sample it
        if (flow_count > 0) {
            // if counter is over the threshold, reset and leave meta.flip_r as
            // is, else increment and set it to false
            if (flow_count >= meta.tau) {
                meta.data.flow_count = flow_count;
                reg_counters.write(meta.flow_id, 0);
            } else {
                meta.flip_r = 0;
                flow_count = flow_count + 1;
                reg_counters.write(meta.flow_id, flow_count);
            }
        } else {
            // set meta.flip_r to false since we don’t want to report
            meta.flip_r = 0;
            if (meta.flip_s == 1) {
                reg_counters.write(meta.flow_id, counter_start);
            }
        }
    }

    apply {
        // TODO: remove, for testing purposes
        standard_metadata.egress_spec = 2;

        if(hdr.ipv4.isValid()) {
            // if we have an entry hit, we get the group parameters and can proceed
            if (groups.apply().hit) {
                // simulate coin flips
                flip();
                /*
                // counter lookup
                updateAndCheck();
                */
                if (meta.flip_r == 1) {
                    sendReport();
                }
            } else {
                sendHello();
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
        // Packets aren’t changed (yet), nothing to do here
     }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        //TODO: add support for ipv6 and udp
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
