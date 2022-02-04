/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_UDP = 17;

/*************************************************************************
************************** H E A D E R S *********************************
*************************************************************************/

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
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

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header dns_t {
    bit<16> id;
    bit<1> isResponse;
    bit<4> opCode;
    bit<1> authAnswer;
    bit<1> trunc;
    bit<1> recurDesired;
    bit<1> recurAvail;
    bit<3> reserved;
    bit<4> respCode;
    bit<16> qdCount;
    bit<16> anCount;
    bit<16> nsCount;
    bit<16> arCount;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    dns_t        dns;
}

/*************************************************************************
*************************** P A R S E R **********************************
*************************************************************************/

parser DnsParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    /* start parsing */
    state start {
        /* parse ethernet packet */
        transition parse_ethernet;
    }

    /* start parsing ethernet packet */
    state parse_ethernet {
        /* extract ethernet packet from input packet */
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            /* parse IP packet */
            TYPE_IPV4: parse_ipv4;
            default: accept;
       }
    }

    /* start parsing IP packet */
    state parse_ipv4 {
        /* extract IP packet from ethernet packet */
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            /* parse UDP packet */
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    /* start parsing UDP packet */
    state parse_udp {
        /* extract DNS packet from UDP packet */
        packet.extract(hdr.udp)
        transition select(hdr.udp.dstPort == 53) {
            /* parse DNS packet */
            true: parse_dns;
            false: accept;
        }
    }

    /* start parsing DNS packet */
    state parse_dns {
        /* extract DNS data in DNS packet */
        packet.extract(hdr.dns);
        transition accept;
    }
}

/*************************************************************************
************** C H E C K S U M     V E R I F I C A T I O N ***************
*************************************************************************/

control DnsVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {

    }
}

/*************************************************************************
****************** I N G R E S S    P R O C E S S I N G ******************
*************************************************************************/

control DnsIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr) {
        /* TODO: fill out code in action body */
    }

    apply {
        /* TODO: fix ingress control logic
         *  - ipv4_lpm should be applied only when IPv4 header is valid
         */
    }
}

/*************************************************************************
******************* E G R E S S     P R O C E S S I N G ******************
*************************************************************************/

control DnsEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {

    }
}

/*************************************************************************
*************** C H E C K S U M     C O M P U T A T I O N ****************
*************************************************************************/

control DnsComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {

    }
}

/*************************************************************************
************************** D E P A R S E R *******************************
*************************************************************************/

control DnsDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.dns);
    }
}

/*************************************************************************
*************************** S W I T C H **********************************
*************************************************************************/

V1Switch(DnsParser(), DnsVerifyChecksum(), DnsIngress(), DnsEgress(), DnsComputeChecksum(), DnsDeparser()) main;
