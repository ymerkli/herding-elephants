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

class HerdController(object):
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
        p_sampling (float):                     The probability to sample a flow (s) [0-1]
        seen_flows (dict):                      A dict of flows the Controller has already seen and has already
                                                sent a hello for
        hellos (int):                           The number of hellos the controller has received from the data plane
        reports (int):                          The number of reports the controler has received from the data plane
        hello_timeouts (int):                   The number of times the connection to the coordinator timed out when
                                                the Controller tried to send a hello
        report_timeouts (int):                  The number of times the connection to the coordinator timed out when
                                                the Controller tried to send a report
    '''

    def __init__(self, sw_name, epsilon, global_threshold_T, sampling_probability_s, coordinator_port, verbose):

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
        self.p_sampling         = sampling_probability_s
        # Debugging
        self.seen_flows         = {}
        self.hellos             = 0
        self.reports            = 0
        self.hello_timeouts     = 0
        self.report_timeouts    = 0
        self.verbose            = verbose

        self.init()

    def init(self):
        '''
        Initialize controller
        '''

        self.coordinator_c._config['async_request_timeout'] = None
        self.coordinator_c._config['sync_request_timeout'] = None

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
        sampling_probability = int((2**32 - 1)*self.p_sampling)

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

    def unpack_digest(self, msg, num_samples):
        '''
        Unpacks a digest received from the data plane

        Args:
            msg ():             The received message
            num_samples (int):  Number of samples

        Returns:
            digest (list):      An array of flow_info's (dicts), where we store the flow 5-tuple (key 'flow')
                                and the flow_count (int) (key flow_count)
        '''

        digest = []
        starting_index = 32
        for sample in range(num_samples):
            srcIP, dstIP, srcPort, dstPort, protocol, flow_count  = struct.unpack(">LLHHBL", msg[starting_index:starting_index + 17])

            # convert int IPs to str
            srcIP = str(ipaddress.IPv4Address(srcIP))
            dstIP = str(ipaddress.IPv4Address(dstIP))

            # construct flow tuple
            flow = (srcIP, dstIP, srcPort, dstPort, protocol)
            flow_info = {
                'flow': flow,
                'flow_count': flow_count
            }
            digest.append(flow_info)

        return digest

    def recv_msg_digest(self, msg):
        '''
        Handles a received digest message. Unpacks the digest using self.unpack_digest() and then
        send a hello or a report to the Coordinator

        Args:
            msg: The received digest message
        '''

        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi", msg[:32])

        digest = self.unpack_digest(msg, num)

        for flow_info in digest:
            # if the 5-tuple is all zero, we got an error message
            flow        = flow_info['flow']
            flow_count  = flow_info['flow_count']
            if flow == (str(ipaddress.IPv4Address(0)),str(ipaddress.IPv4Address(0)),0,0,0):
                self.handle_Error(flow_count)
            else:
                # if the flow count is zero, the digest is just a hello message
                # otherwise, it's a report
                srcGroup, dstGroup = self.extract_group(flow)
                group = (srcGroup, dstGroup)
                if flow_count == 0:
                    self.hellos += 1
                    # only send a hello if we havent sent a hello yet for this flow
                    if flow not in self.seen_flows:
                        self.send_hello(flow)
                        self.seen_flows[flow] = 1
                else:
                    self.report_flow(flow)
                    self.reports += 1

        #Acknowledge digest
        self.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)

    def run_digest_loop(self):
        '''
        The blocking function that will be running on the controller.
        Waits for new digests and passes them on
        '''

        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        notifications_socket = self.controller.client.bm_mgmt_get_info().notifications_socket
        sub.connect(notifications_socket)
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')

        print("Switch {0}: starting digest loop".format(self.sw_name))

        while True:
            msg = sub.recv()
            self.recv_msg_digest(msg)


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
                # if the flow count is zero, the digest is just a hello message
                # otherwise, it's a report
                srcGroup, dstGroup = self.extract_group(flow)
                group = (srcGroup, dstGroup)
                if flow_count == 0:
                    # only send a hello if we havent sent a hello yet for this flow
                    if flow not in self.seen_flows:
                        self.hellos += 1
                        self.send_hello(flow)
                        self.seen_flows[flow] = 1
                else:
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

    def send_hello(self, flow):
        '''
        Sends a hello message to the central coordinator, notifying that the switch has seen
        a flow it's never seen before. We also send a callback to the coordinator, through
        which the coordiantor can send back the l_g. The coordinator will store the callback
        in case our l_g needs to be updated

        Args:
            flow (): The new flow 5-tuple we want to let the Coordinator know about
        '''

        try:
            self.coordinator_c.root.send_hello(flow, self.sw_name, self.hello_callback)
        except Exception as e:
            print("Error: {0} couldnt send hello for {1}: {2}".format(self.sw_name, flow, e))
            self.hello_timeouts += 1

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

        if not self.verbose:
            blockPrint()
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

        if not self.verbose:
            enablePrint()

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
        Shutdown handling
        '''
        count_hello_switch = self.controller.register_read("count_hellos")
        count_report_switch = self.controller.register_read("count_reports")

        print("{0}: switch hellos={1}, recv hellos={2}, switch reports={3}, recv reports={4}".format(self.sw_name,\
            count_hello_switch, self.hellos, count_report_switch, self.reports))

        print("{0}: hello timeouts={1}, report timeouts={2}".format(self.sw_name, self.hello_timeouts, self.report_timeouts))
        mem_used = 0
        for i in range (1,4):
            switch_mem = self.controller.register_read("hash_table_{}".format(i))
            for place in switch_mem:
                if(place != 0):
                    mem_used += 1

        f = open("../evaluation/counters/counter_results_herd","a")
        f.write("{0}: switch hellos={1}, recv hellos={2}, switch reports={3}, recv reports={4}\nSwitch memory used: {5}".format(self.sw_name,\
            count_hello_switch, self.hellos, count_report_switch, self.reports, mem_used))


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

    parser.add_argument(
        "--v",
        action="store_true"
    )

    args = parser.parse_args()

    if (args.s < 0 or 1 < args.s):
        raise InputValueError

    if (args.e <= 0 or 1 < args.e):
        raise InputValueError

    return args.n, args.e, args.t, args.s, args.p, args.v

if __name__ == '__main__':
    #sys.tracebacklimit = 0
    try:
        sw_name, epsilon, global_threshold_T, sampling_probability_s, coordinator_port, verbose = parser()
        herd_controller = HerdController(sw_name, epsilon, global_threshold_T, sampling_probability_s, coordinator_port, verbose)

        print("Herd controller of switch %s ready" % herd_controller.sw_name)

        # register signal handler to handle shutdowns
        signal.signal(signal.SIGINT, herd_controller.signal_handler)

        herd_controller.run_cpu_port_loop()

    except InputValueError:
        print("The sampling probability should be between 0 and 1")
