import socket
import struct
import pickle
import os
import rpyc
import nnpy
import argparse

from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
from crc import Crc
from rpyc.utils.server import ThreadedServer
from scapy.all import Ether, sniff, Packet, BitField

class L2Controller(object):
    '''
    The controller that is running on each switch and will be communicating with
    the central coordiantor

    Args:

    Attributes:
        topo (p4utils.utils.topology.Topology): The switch topology
        sw_name (str): The name of the switch
        thrift_port (int): The thrift port of the switch
        controller (p4utils.utils.sswitch_API.SimpleSwitchAPI): The controller of the switch
        coordinator_c (rpyc connection): An rpyc connection to the Coordinator
    '''

    def __init__(self, sw_name):

        self.topo          = Topology(db="topology.db")
        self.sw_name       = sw_name
        self.thrift_port   = self.topo.get_thrift_port(sw_name)
        self.controller    = SimpleSwitchAPI(self.thrift_port)

        self.coordinator_c = rpyc.connect('localhost', 18812)

        self.init()

    def init(self):

        self.controller.reset_state()

    def unpack_digest(self, msg, num_samples):

        digest = []
        print(len(msg), num_samples)
        starting_index = 32
        for sample in range(num_samples):
            mac0, mac1, ingress_port = struct.unpack(">LHH", msg[starting_index:starting_index+8])
            starting_index +=8
            mac_addr = (mac0 << 16) + mac1
            digest.append((mac_addr, ingress_port))

        return digest

    def recv_msg_digest(self, msg):

        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi", msg[:32])
        digest = self.unpack_digest(msg, num)
        self.report_flow(digest)

        #Acknowledge digest
        self.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)

    def run_digest_loop(self):

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
        '''

        self.coordinator_c.root.send_report(flow)
    
    def send_hello(self, flow):
        '''
        Sends a hello message to the central coordinator, notifying that the switch has seen
        a flow it's never seen before. We also send a callback to the coordinator, through 
        which the coordiantor can send back the l_g. The coordinator will store the callback
        in case our l_g needs to be updated

        Args:
            flow (): The new flow we want to report
        '''

        self.coordinator_c.root.send_hello(flow, self.sw_name, self.hello_callback)

    def hello_callback(self, flow, l_g):
        '''
        The callback function for the coordinator to receive the update l_g
        '''


def parser():
    parser = argparse.ArgumentParser(description='parse the keyword arguments')

    parser.add_argument(
            "--n",
            type=str,
            required=True,
            help="The name of the switch"
    )

    args = parser.parse_args()

    return args.n

if __name__ == '__main__':
    sw_name = parser()

    l2_controller = L2Controller(sw_name)

    l2_controller.run_digest_loop()