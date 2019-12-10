import socket
import struct
import pickle
import os
import rpyc
import nnpy
import argparse
import ipaddress
import re
import math
import signal
import sys

from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
## from crc import Crc
from rpyc.utils.server import ThreadedServer
from scapy.all import Ether, sniff, Packet, BitField, hexdump

# Copied from the excercises (taken from wikipedia probably), not all are needed
crc32_polinomials = [0x04C11DB7, 0xEDB88320, 0xDB710641, 0x82608EDB, 0x741B8CD7, 0xEB31D82E,
                     0xD663B05, 0xBA0DC66B, 0x32583499, 0x992C1A4C, 0x32583499, 0x992C1A4C]

'''
Used for clone method of receiving packets. Defines the same fields as
the cpu header of switch.p4



'''

class Cpu_Header(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('srcAddr',0,32),
                    BitField('dstAddr', 0, 32),
                    BitField('srcPort', 0, 16),
                    BitField('dstPort', 0, 16),
                    BitField('protocol', 0, 8), BitField('flow_count', 0, 32)]

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
    '''

    def __init__(self, sw_name, epsilon, global_threshold_T, sampling_probability_s, coordinator_port):

        # Core functionality
        self.topo               = Topology(db="topology.db")
        self.sw_name            = sw_name
        self.thrift_port        = self.topo.get_thrift_port(sw_name)
        self.controller         = SimpleSwitchAPI(self.thrift_port)
        self.coordinator_c      = rpyc.connect('localhost', coordinator_port)
        self.custom_calcs       = self.controller.get_custom_crc_calcs()
        self.cpu_port           = self.topo.get_cpu_port_index(self.sw_name)
        # Parmeters
        self.epsilon            = float(epsilon)
        self.global_threshold_T = float(global_threshold_T)
        self.p_sampling         = sampling_probability_s
        # Debugging
        self.sent_hellos        = {}
        self.hellos             = 0
        self.reports            = 0

        self.init()

    def init(self):
        '''
        Initialize controller
        '''

        self.controller.reset_state()

        self.set_crc_custom_hashes()

        self.write_p_sampling_to_switch()

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


    def write_p_sampling_to_switch(self):
        '''
        Writes the registers needed to initialize counters in the switch.
        '''

        counter_startvalue = int(1/self.p_sampling)
        # convert to uint32_probability
        sampling_probability = (2**32 - 1)*self.p_sampling

        # register names are defined in switch.p4
        self.controller.register_write("sampling_probability", 0, sampling_probability)
        self.controller.register_write("count_start", 0, counter_startvalue)

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
            msg (): The received digest message
        '''

        packet = Ether(str(pkt))

        if packet.type == 0x1234:
            cpu_header  = Cpu_Header(packet.payload)
            flow        = (str(ipaddress.IPv4Address(cpu_header.srcAddr)), str(ipaddress.IPv4Address(cpu_header.dstAddr)), cpu_header.srcPort, cpu_header.dstPort, cpu_header.protocol)
            flow_count  = int(cpu_header.flow_count)

            if flow == (str(ipaddress.IPv4Address(0)),str(ipaddress.IPv4Address(0)),0,0,0):
                self.handle_Error(flow_count)
            else:
                # if the flow count is zero, the digest is just a hello message
                # otherwise, it's a report
                srcGroup, dstGroup = self.extract_group(flow)
                group = (srcGroup, dstGroup)
                if flow_count == 0:
                    # only send a hello if we havent sent a hello yet for this flow
                    self.hellos = self.hellos + 1
                    if flow not in self.sent_hellos:
                        self.send_hello(flow)
                        self.sent_hellos[flow] = 1
                else:
                    self.reports = self.reports + 1
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

        self.coordinator_c.root.send_report(flow, self.sw_name)

    def send_hello(self, flow):
        '''
        Sends a hello message to the central coordinator, notifying that the switch has seen
        a flow it's never seen before. We also send a callback to the coordinator, through
        which the coordiantor can send back the l_g. The coordinator will store the callback
        in case our l_g needs to be updated

        Args:
            flow (): The new flow 5-tuple we want to let the Coordinator know about
        '''

        self.coordinator_c.root.send_hello(flow, self.sw_name, self.hello_callback)

    def hello_callback(self, flow, l_g):
        '''
        The callback function for the coordinator to receive the update l_g
        Will call the add_group_values function to update the group based values for
        the new value of l_g

        Args:
            flow (tuple):   The flow 5-tuple for which we sent a hello
            l_g (int):      The locality parameter l_g for the group to which flow belongs
        '''

        self.add_group_values(flow, l_g)

    def add_group_values(self, flow, l_g):
        '''
        Calculates the group values tau_g and r_g from the stored l_g and then writes
        these values into the group_values table.
        The use of these values are:
            tau_g (int):    The mule threshold (i.e. report threshold) of group g.
                            If a mole count exceeds this threshold, the flow is reported to the coordinator.
            r_g (int):      The report probability for group g. If we found a mule,
                            we report to the coordinator with probability r_g

        Args:
            flow (tuple):   The flow for which we want the group values
            l_g (int):      The locality parameter l_g for the group to which flow belongs
        '''

        tau_g = math.ceil(self.epsilon * self.global_threshold_T / float(l_g))
        tau_g = int(tau_g)

        r_g   = 1 / float(l_g)

        srcGroup, dstGroup = self.extract_group(flow)

        # convert r_g to use in coinflips on the switch (no floating point)
        r_g = (2**32 - 1) * r_g
        r_g = int(r_g) # convert back to int

        '''
        Add an entry to the group_values table. In case the group already has
        an entry, this wont do anything and return a value
        '''
        self.controller.table_add('group_values', 'getValues',\
            [srcGroup, dstGroup], [str(r_g), str(tau_g)])

        '''
        In case the group already had an entry, the table_add won't update it
        and simply return a warning. We simply do a table_update after every
        single table_add. This doesn't hurt for new group adds and correctly
        updates the group values for already existing groups
        '''
        entry_handle = self.controller.get_handle_from_match('group_values',\
            [srcGroup, dstGroup])

        self.controller.table_modify('group_values', 'getValues',\
            entry_handle, [str(r_g), str(tau_g)])

    def extract_group(self, flow):
        '''
        Extracts the group of the given IP (i.e. the first 8 bits of
        the srcIP and first 8 bits of the dstIP

        Args:
            flow (tuple):   The flow for which we want the group values

        Returns:
            group (tuple): 2-tuple with srcGroup and dstGroup
        '''
        # stringify digest IPs
        srcIP_str = str(flow[0])
        dstIP_str = str(flow[1])

        # extract group ids (i.e. the first 8 bits of the IPv4 src and dst addresses) from IPs using regex
        # raises an error if the digest IPs have invalid format
        #TODO: IPv6?
        srcGroup = re.match(r'\b(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', srcIP_str)
        if srcGroup is None:
            raise ValueError("Error: invalid srcIP format: {0}".format(srcIP_str))
        else:
            srcGroup = srcGroup.group(1)

        dstGroup = re.match(r'\b(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', dstIP_str)
        if dstGroup is None:
            raise ValueError("Error: invalid srcIP format: {0}".format(dstIP_str))
        else:
            dstGroup = dstGroup.group(1)

        return srcGroup, dstGroup


    def signal_handler(self, sig, frame):
        '''
        reads counts from switch and writes them to a file when the terminate
        signal is sent.
        '''
        count_hello_switch = self.controller.register_read("count_hellos")

        count_report_switch = self.controller.register_read("count_reports")
        f = open("counts.txt", "a")
        f.write('Switch %s:\nReceived hellos: %s, Sent hellos: %s \nReceived reports: %s, Sent reports: %s\n' % (self.sw_name, self.hellos, count_hello_switch, self.reports, count_report_switch ))
        f.close()
        print('Switch %s:\nReceived hellos: %s, Sent hellos: %s \nReceived reports: %s, Sent reports: %s\n' % (self.sw_name, self.hellos, count_hello_switch, self.reports, count_report_switch ))
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
            "--s",
            type=float,
            required=True,
            help="The sampling probability s"
    )

    parser.add_argument(
            "--p",
            type=int,
            required=False,
            default=18812,
            help="The port where the coordinator server is running on"
    )

    args = parser.parse_args()

    if (args.s < 0 or 1 < args.s):
        raise InputValueError

    if (args.e <= 0 or 1 < args.e):
        raise InputValueError

    return args.n, args.e, args.t, args.s, args.p

if __name__ == '__main__':
    try:
        sw_name, epsilon, global_threshold_T, sampling_probability_s, coordinator_port = parser()
        l2_controller = L2Controller(sw_name, epsilon, global_threshold_T, sampling_probability_s, coordinator_port)

        print("L2 controller of switch %s ready" % l2_controller.sw_name)

        signal.signal(signal.SIGINT, l2_controller.signal_handler)

        l2_controller.run_cpu_port_loop()

        # register signal handler to handle shutdowns
        signal.signal(signal.SIGINT, l2_controller.signal_handler)

    except InputValueError:
        print("The sampling probability should be between 0 and 1")
