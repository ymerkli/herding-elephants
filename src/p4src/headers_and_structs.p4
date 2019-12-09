// Typedefs //
// Used for threshold variables
typedef bit<32> tau_t;
// Probabilities converted as: u_p = 2^32*p - 1, p in (0,1)
typedef bit<32> uint32_probability;
// Used for hashes of a flow five tuple
typedef bit<32> flow_id_t;

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9> egressSpec_t;

// Constants //
const uint32_probability INT32_MAX = 4294967295;
const bit<16> ipv4_type = 0x800;
const bit<16> CLONE_ETHER_TYPE = 0x1234;

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

// Used by hash functions and the table lookup to store data
struct hash_data_t {
    flow_id_t hash_key;
    flow_id_t read_key;
    bit<32> hash_table_entry;
    bit<64> value;
}

// Used for the group table lookup
struct flow_group_t {
    bit<8> srcGroup;
    bit<8> dstGroup;
}

// We need fields for: 2 coinflips,
//                     1 local threshold,
//                     1 report_data struct for digest command
//                     1 hash_data struct for counter lookup
//                     1 found_flag to indicate which table we are operating on
//                     1 flow_group struct for the group_values table lookup
struct metadata {
    uint32_probability flip_s;
    uint32_probability flip_r;
    tau_t tau;
    report_data_t data;
    hash_data_t hash_data;
    bit<2> found_flag;
    flow_group_t group;

    bit<14> ecmp_hash;
    bit<14> ecmp_group_id;
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


header cpu_t {
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<8>    protocol;
    bit<32> flow_count;

}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    cpu_t cpu;
}
