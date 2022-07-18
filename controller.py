#!/usr/bin/env python3
import argparse
import os
import sys
from time import sleep

import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

def writeIpv4Table(p4info_helper, sw, port, dest_eth_addr, dest_ip_addr):
    table_entry = p4info_helper.buildTableEntry(
        table_name="DnsIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dest_ip_addr, 32)
        },
        action_name="DnsIngress.ipv4_forward",
        action_params={
            "dstAddr": dest_eth_addr,
            "port": port
        }
    )
    sw.WriteTableEntry(table_entry)
    print("Installed IPV4 Forwading Table on %s" % sw.name)

def writeDNSTable(p4info_helper, sw, query, ip_addr):
    qlen = len(query)
    q_inbytes = bytes(query + "\0", 'ascii')
    q_inint = int.from_bytes(q_inbytes, byteorder='big', signed=True)

    table_entry = p4info_helper.buildTableEntry(
        table_name="DnsIngress.dns_table" + str(qlen),
        match_fields={
            "hdr.dns_querytext.query" + str(qlen) + ".text": q_inint
        },
        action_name="DnsIngress.dns_found",
        action_params={
            "answer": ip_addr
        }
    )
    sw.WriteTableEntry(table_entry)
    print("Installed DNS Table on %s" % sw.name)

def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    #Sampling for DNS Table with 4 chars
    dnstable4 = {}

    try:
        print("Starting DNS Controller...")

        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s2")

        #Populate S1 Tables
        writeIpv4Table(p4info_helper, sw=s1, port=1,
                         dest_eth_addr="08:00:00:00:01:11", dest_ip_addr="10.0.1.1")
        writeIpv4Table(p4info_helper, sw=s1, port=2,
                         dest_eth_addr="08:00:00:00:01:22", dest_ip_addr="10.0.2.2")
        writeIpv4Table(p4info_helper, sw=s1, port=3,
                         dest_eth_addr="08:00:00:00:02:00", dest_ip_addr="10.0.3.3")
        writeIpv4Table(p4info_helper, sw=s1, port=3,
                         dest_eth_addr="08:00:00:00:02:00", dest_ip_addr="8.8.8.8")                         
        writeDNSTable(p4info_helper, sw=s1, query="abcd", ip_addr="10.0.1.1")
        dnstable4["abcd"] = "10.0.2.2"
        writeDNSTable(p4info_helper, sw=s1, query="xyz", ip_addr="10.0.2.2")
        writeDNSTable(p4info_helper, sw=s1, query="mn", ip_addr="10.0.4.4")

        #Populate S2 Tables
        writeIpv4Table(p4info_helper, sw=s2, port=1,
                         dest_eth_addr="08:00:00:00:01:00", dest_ip_addr="10.0.1.1")
        writeIpv4Table(p4info_helper, sw=s2, port=1,
                         dest_eth_addr="08:00:00:00:01:00", dest_ip_addr="10.0.2.2")
        writeIpv4Table(p4info_helper, sw=s2, port=2,
                         dest_eth_addr="08:00:00:00:02:11", dest_ip_addr="10.0.3.3")
        writeDNSTable(p4info_helper, sw=s2, query="cruzeiro", ip_addr="10.0.3.3")
        writeDNSTable(p4info_helper, sw=s2, query="atletico", ip_addr="10.0.3.4")

        while (True):
            pacoteChegada = s1.PacketIn()
            print("Tipo do Pacote: ", pacoteChegada)
    except KeyboardInterrupt:
        print("Closing DNS Controller...")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4DNS Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/dnsserver.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/dnsserver.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
