/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

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
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
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
    bit<1> reserved;
    bit<1> authenticData;
    bit<1> checkingDisabled;
    bit<4> respCode;
    bit<16> qCount;
    bit<16> answerCount;
    bit<16> authRec;
    bit<16> addrRec;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*************************** P A R S E R **********************************
*************************************************************************/

parser DnsParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /* TODO: add parser logic */
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
        /* TODO: add deparser logic */
    }
}

/*************************************************************************
*************************** S W I T C H **********************************
*************************************************************************/

V1Switch(DnsParser(), DnsVerifyChecksum(), DnsIngress(), DnsEgress(), DnsComputeChecksum(), DnsDeparser()) main;
