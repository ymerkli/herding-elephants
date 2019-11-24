import socket
import struct
import pickle
import os
import rpyc
import nnpy
import argparse
import re
import ipaddress

from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
#from crc import Crc
from rpyc.utils.server import ThreadedServer
from scapy.all import Ether, sniff, Packet, BitField

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

    def __init__(self, sw_name, epsilon, global_threshold_T):

        self.topo               = Topology(db="../topology.db")
        self.sw_name            = sw_name
        self.thrift_port        = self.topo.get_thrift_port(sw_name)
        self.controller         = SimpleSwitchAPI(self.thrift_port)
        self.epsilon            = epsilon
        self.global_threshold_T = global_threshold_T

        self.coordinator_c = rpyc.connect('localhost', 18812)

        self.init()

    def init(self):

        self.controller.reset_state()

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
            srcIP, dstIP, srcPort, dstPort, protocol, flow_count  = struct.unpack(">LLHHBH", msg[starting_index:])
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

        tau_g = self.epsilon * self.global_threshold_T / l_g
        tau_g = int(tau_g) # cast to int for adding to table
        r_g   = 1 / l_g

        print("flow: {0}, tau_g: {1}, r_g:{2}".format(flow, tau_g, r_g))

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

        # pad groups to IPs
        # eg srcGroup <10> becomes <10.0.0.0>
        srcGroup = "{0}.0.0.0".format(srcGroup)
        dstGroup = "{0}.0.0.0".format(dstGroup)

        # add an entry to the group_values table
        self.controller.table_add('group_values', 'getValues',\
            [srcGroup, dstGroup], [str(r_g), str(tau_g)])


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

    args = parser.parse_args()

    return args.n, args.e, args.t

if __name__ == '__main__':
    sw_name, epsilon, global_threshold_T = parser()

    l2_controller = L2Controller(sw_name, epsilon, global_threshold_T)

    l2_controller.run_digest_loop()