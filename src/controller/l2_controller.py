import socket
import struct
import pickle
import os
import rpyc
import nnpy
import argparse
import ipaddress
import re

from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
## from crc import Crc
from rpyc.utils.server import ThreadedServer
from scapy.all import Ether, sniff, Packet, BitField

# Copied from the excercises (taken from wikipedia probably), not all are needed
crc32_polinomials = [0x04C11DB7, 0xEDB88320, 0xDB710641, 0x82608EDB, 0x741B8CD7, 0xEB31D82E,
                     0xD663B05, 0xBA0DC66B, 0x32583499, 0x992C1A4C, 0x32583499, 0x992C1A4C]


class L2Controller(object):
    '''
    The controller that is running on each switch and will be communicating with
    the central coordiantor

    Args:
        sw_name (str):              The name of the switch where the controller is running on
        epsilon (int):              The approximation factor
        global_threshold_T (int):   The global threshold

    Attributes:
        topo (p4utils Topology):                The switch topology
        sw_name (str):                          The name of the switch
        thrift_port (int):                      The thrift port of the switch
        controller (p4utils SimpleSwitchAPI):   The controller of the switch
        coordinator_c (rpyc connection):        An rpyc connection to the Coordinator
        epsilon (int):                          The approximation factor
        global_threshold_T (int):               The global threshol
    '''

    def __init__(self, sw_name, epsilon, global_threshold_T, sampling_probability_s):

        self.topo               = Topology(db="../topology.db")
        self.sw_name            = sw_name
        self.thrift_port        = self.topo.get_thrift_port(sw_name)
        self.controller         = SimpleSwitchAPI(self.thrift_port)
        self.epsilon            = epsilon
        self.global_threshold_T = global_threshold_T
        self.p_sampling         = sampling_probability_s
        self.coordinator_c      = rpyc.connect('localhost', 18812)
        self.custom_calcs       = self.controller.get_custom_crc_calcs()

        self.init()


    def init(self):

        self.controller.reset_state()

        print("Setting crc polynomials")
        self.set_crc_custom_hashes()

        print("Writing sampling probability to switch")
        self.write_p_sampling_to_switch(self.p_sampling)
        print("Written counter start:")
        print(self.controller.register_read("count_start"))
        print("Written probability:")
        print(self.controller.register_read("sampling_probability"))


    def set_crc_custom_hashes(self):
        '''
        Passes the custom crc32 polynomials to the switch
        '''

        i = 0
        for custom_crc32, width in sorted(self.custom_calcs.items()):
            self.controller.set_crc32_parameters(custom_crc32, crc32_polinomials[i], 0xffffffff, 0xffffffff, True, True)
            i+=1


    def write_p_sampling_to_switch(self, p_sampling):
        '''
        Writes the registers needed to initialize counters in the switch.

        Args:
            p_sampling:         The probability to sample a flow (s) [0-1]

        '''

        counter_startvalue = int(1/p_sampling)
        # convert to uint32_probability
        sampling_probability = (2**32 - 1)*p_sampling

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
            print(ipaddress.IPv4Address(srcIP), ipaddress.IPv4Address(dstIP), srcPort, dstPort, protocol, flow_count)

            # convert int IPs to str
            srcIP = ipaddress.IPv4Address(srcIP)
            dstIP = ipaddress.IPv4Address(dstIP)

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
            msg (): The received digest message
        '''

        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi", msg[:32])

        digest = self.unpack_digest(msg, num)

        for flow_info in digest:
            # if the 5-tuple is all zero, we got an error message
            if flow_info['flow'] == (ipaddress.IPv4Address(0),ipaddress.IPv4Address(0),0,0,0):
                self.handle_Error(flow_info['flow_count'])
            else:
            # if the flow count is zero, the digest is just a hello message
            # otherwise, it's a report
                if flow_info['flow_count'] == 0:
                    print('sending a hello for: ', flow_info['flow'])
                    self.send_hello(flow_info['flow'])
                else:
                    print('sending a report for: ', flow_info['flow'])
                    self.report_flow(flow_info['flow'])

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

        while True:
            msg = sub.recv()
            self.recv_msg_digest(msg)


    def report_flow(self, flow):
        '''
        Reports a mule flow to the central coordinator

        Args:
            flow (tuple):   The flow 5-tuple to be reported
        '''

        self.coordinator_c.root.send_report(flow)

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

        print('hello callback: flow=', flow, ', l_g=', l_g)
        self.add_group_values(flow, l_g)

    def add_group_values(self, flow, l_g):
        '''
        Calculates the group values tau_g and r_g from the stored l_g and then writes
        these values into the group_values table

        Args:
            flow (tuple):   The flow for which we want the group values
            l_g (int):      The locality parameter l_g for the group to which flow belongs
        '''

        tau_g = int(self.epsilon * self.global_threshold_T / l_g)
        r_g   = 1 / l_g

        print("flow: {0}, tau_g: {1}, r_g:{2}".format(flow, tau_g, r_g))

        # convert r_g to use in coinflips on the switch (no floating point)
        r_g = (2**32 - 1) * r_g

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

        # add an entry to the group_values table
        self.controller.table_add('group_values', 'getValues',\
            [srcGroup, dstGroup], [str(r_g), str(tau_g)])

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

    args = parser.parse_args()

    if (args.s < 0 or 1 < args.s):
        raise InputValueError

    if (args.e <= 0 or 1 < args.e):
        raise InputValueError

    return args.n, args.e, args.t, args.s

if __name__ == '__main__':
    try:
        sw_name, epsilon, global_threshold_T, sampling_probability_s = parser()
        l2_controller = L2Controller(sw_name, epsilon, global_threshold_T, sampling_probability_s)

        l2_controller.run_digest_loop()

    except InputValueError:
        print("The sampling probability should be between 0 and 1")
