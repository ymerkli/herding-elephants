import socket
import struct
import pickle
import os
import sys
import rpyc
import nnpy
import argparse
import ipaddress
import re
import math
import time
import signal
import sys
import gc; gc.disable()

from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
## from crc import Crc
from rpyc.utils.server import ThreadedServer
from scapy.all import Ether, sniff, Packet, BitField, hexdump

# Copied from the excercises (taken from wikipedia probably), not all are needed
crc32_polinomials = [0x04C11DB7, 0xEDB88320, 0xDB710641, 0x82608EDB, 0x741B8CD7, 0xEB31D82E,
                     0xD663B05, 0xBA0DC66B, 0x32583499, 0x992C1A4C, 0x32583499, 0x992C1A4C]

# Disable prints
def blockPrint():
    sys.stdout = open(os.devnull, 'w')

# Restore prints
def enablePrint():
    sys.stdout = sys.__stdout__

'''
Used for clone method of receiving packets. Defines the same fields as
the cpu header of switch.p4



'''
class Cpu_Header(Packet):
    name = 'CpuPacket'
    fields_desc = [ BitField('srcAddr', 0, 32),
                    BitField('dstAddr', 0, 32),
                    BitField('srcPort', 0, 16),
                    BitField('dstPort', 0, 16),
                    BitField('protocol', 0, 8),
                    BitField('flow_count', 0, 32)]

class L2Controller(object):
    '''
    The controller that is running on each switch and will be communicating with
    the central coordiantor

    Args:
        sw_name (str):                  The name of the switch where the controller is running on
        epsilon (float):                The approximation factor
        global_threshold_T (int):       The global threshold
        sampling_probability_s (float): The probability to sample a flow (s) [0-1]
        coordinator_port (int):         The port on which the coordinator server is running on

    Attributes:
        topo (p4utils Topology):                The switch topology
        sw_name (str):                          The name of the switch
        thrift_port (int):                      The thrift port of the switch
        controller (p4utils SimpleSwitchAPI):   The controller of the switch
        coordinator_c (rpyc connection):        An rpyc connection to the Coordinator
        epsilon (int):                          The approximation factor
        global_threshold_T (float):             The global threshold (float to prevent integer division)
        reports (int):                          The number of reports the controler has received from the data plane
        report_timeouts (int):                  The number of times the connection to the coordinator timed out when
                                                the L2Controller tried to send a report
    '''

    def __init__(self, sw_name, epsilon, global_threshold_T, coordinator_port):

        # Core functionality
        self.topo               = Topology(db="topology.db")
        self.sw_name            = sw_name
        self.thrift_port        = self.topo.get_thrift_port(sw_name)
        self.controller         = SimpleSwitchAPI(self.thrift_port)
        self.coordinator_c      = rpyc.connect('localhost', coordinator_port, keepalive=True)
        self.custom_calcs       = self.controller.get_custom_crc_calcs()
        self.cpu_port           = self.topo.get_cpu_port_index(self.sw_name)
        # Parmeters
        self.epsilon            = float(epsilon)
        self.global_threshold_T = float(global_threshold_T)
        # Evaluation
        self.reports            = 0
        self.report_timeouts    = 0

        self.init()

    def init(self):
        '''
        Initialize controller
        '''

        self.coordinator_c._config['async_request_timeout'] = None
        self.coordinator_c._config['sync_request_timeout'] = None

        self.controller.reset_state()

        self.set_crc_custom_hashes()

        self.write_threshold_to_switch()

        self.fill_ipv4_lpm_table()

        self.add_mirror()


    def add_mirror(self):
        '''
        Copied from the exercise, tells the controller on which port to listen
        '''
        if self.cpu_port:
            self.controller.mirroring_add(100, self.cpu_port)

    def set_crc_custom_hashes(self):
        '''
        Passes the custom crc32 polynomials to the switch
        '''

        i = 0
        for custom_crc32, width in sorted(self.custom_calcs.items()):
            self.controller.set_crc32_parameters(custom_crc32, crc32_polinomials[i], 0xffffffff, 0xffffffff, True, True)
            i+=1


    def write_threshold_to_switch(self):
        '''
        Writes the report threshold in the switch. k = 1/10 for our setup since
        we have 10 ingress switches.
        '''
        k = 1/10
        report_threshold = int(self.epsilon*self.global_threshold_T*k)

        # register names are defined in switch.p4
        self.controller.register_write("report_threshold", 0, report_threshold)

    def reset_hash_tables(self):
        '''
        Resets the hash tables on the switch

        '''

        for i in range (1,4):
            self.controller.register_reset("hash_table_{}".format(i))

    def handle_Error(self, error_code):
        '''
        Handles received error messages.

        '''
        print("Received error message with error code: %s" % error_code)
        if (error_code == 0):
            self.reset_hash_tables()

    def fill_ipv4_lpm_table(self):
        '''
        Writes the ipv4_lpm table. This table should basically send ALL
        IP traffic to the next aggregating switch. We thus do longest prefix
        match with prefix 0 (i.e. match all IPs)
        '''

        for sw_dst in self.topo.get_p4switches():
            if re.match(r"ag\d+", sw_dst):
                '''
                ingress switches only have connections towards external load balancing
                switches and internal aggreagting switches.
                Aggregating switches (named ag<id>) forward traffic to internal hosts
                '''

                dst_switch_mac = self.topo.node_to_node_mac(sw_dst, self.sw_name)
                sw_port        = self.topo.node_to_node_port_num(self.sw_name, sw_dst)
                match_ip       = unicode("0.0.0.0/0")

                self.controller.table_add("ipv4_lpm", "set_nhop",\
                    [str(match_ip)], [str(dst_switch_mac), str(sw_port)])

                # we only add one single rule for the agregating switch
                break

    def recv_msg_cpu(self, pkt):
        '''
        Handles a received cloned packet. Unpacks the packet using the
        Cpu_Header class and does either send a Hello, Report or does error
        handling.

        Args:
            pkt (scapy.layers.l2.Ether):    The sniffed copy2CPU packet
        '''

        packet = Ether(str(pkt))

        if packet.type == 0x1234:
            cpu_header  = Cpu_Header(packet.payload)
            flow        = ( str(ipaddress.IPv4Address(cpu_header.srcAddr)),\
                            str(ipaddress.IPv4Address(cpu_header.dstAddr)),\
                            cpu_header.srcPort,\
                            cpu_header.dstPort,\
                            cpu_header.protocol\
            )
            flow_count  = int(cpu_header.flow_count)

            if flow == (str(ipaddress.IPv4Address(0)),str(ipaddress.IPv4Address(0)),0,0,0):
                self.handle_Error(flow_count)
            else:
                # we only send reports here since there is no hellos
                self.reports += 1
                self.report_flow(flow)

    def run_cpu_port_loop(self):
        '''
        The blocking function that will be running on the controller.
        Waits for new cloned packets and passes them on to the recv function.
        '''
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        sniff(iface=cpu_port_intf, prn=self.recv_msg_cpu)

    def report_flow(self, flow):
        '''
        Reports a mule flow to the central coordinator

        Args:
            flow (tuple):   The flow 5-tuple to be reported
        '''

        try:
            self.coordinator_c.root.send_report(flow, self.sw_name)
        except Exception as e:
            print("Error: {0} couldnt send report for {1}: {2}".format(self.sw_name, flow, e))
            self.report_timeouts += 1

    def signal_handler(self, sig, frame):
        '''
        Shutdown handling
        '''
        count_report_switch = self.controller.register_read("count_reports")

        print("{0}: switch reports={1}, recv reports={2}".format(self.sw_name,\
            count_report_switch, self.reports))
        f = open("counter_results_rla","a")
        f.write("{0}: switch reports={1}, recv reports={2}\n".format(self.sw_name,\
            count_report_switch, self.reports))

        sys.exit(0)

class InputValueError(Exception):
    pass

def parser():
    parser = argparse.ArgumentParser(description='parse the keyword arguments')

    parser.add_argument(
            "--n",
            type=str,
            required=True,
            help="The name of the switch"
    )

    parser.add_argument(
            "--e",
            type=float,
            required=True,
            help="The approximation factor epsilon"
    )

    parser.add_argument(
            "--t",
            type=int,
            required=True,
            help="The global threshold T"
    )

    parser.add_argument(
            "--p",
            type=int,
            required=False,
            default=18812,
            help="The port where the coordinator server is running on"
    )

    args = parser.parse_args()

    if (args.e <= 0 or 1 < args.e):
        raise InputValueError

    return args.n, args.e, args.t, args.p

if __name__ == '__main__':
    try:
        sw_name, epsilon, global_threshold_T, coordinator_port = parser()
        l2_controller = L2Controller(sw_name, epsilon, global_threshold_T, coordinator_port)

        print("L2 controller of switch %s ready" % l2_controller.sw_name)

        # register signal handler to handle shutdowns
        signal.signal(signal.SIGINT, l2_controller.signal_handler)

        l2_controller.run_cpu_port_loop()

    except InputValueError:
        print("The sampling probability should be between 0 and 1")
