import socket
import struct
import pickle
import os
import rpyc
import nnpy

from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
from crc import Crc
from rpyc.utils.server import ThreadedServer
from scapy.all import Ether, sniff, Packet, BitField

class CoordinatorService(rpyc.Service):
    '''
    The CoordinatorService object is the service running on the Coordinator that aggregates
    partial information observed at each switch to identify network-wide elephants.
    The switches send messages to the Coordinator

    Args:

    Attributes:
        heavy_hitter_set (list):    A list of flows which are heavy hitters
        reports (dict):             A dict of flows and their report count. Key is the flow hash
        elephant_threshold_R(int):  The thresholds on the report count for which we promote a mule to a heavy hitter
        l_g_table (dict):           A dict storing the locality parameter l_g for a flow based on the group g 
                                    to which the flow belongs to. Key is a group_hash, value is an int
        flow_to_switches (dict):    A dict storing which switches have seen a flow. Key is a flow_hash, value is an array
                                    of sw_names
        callback_table (dict):      A dict storing the callbacks received from switches in hello messages.
                                    Callbacks are used to send l_g back to switches. Key is a sw_name (str), value is a function.
    '''

    def __init__(self):
        self.heavy_hitter_set       = []
        self.reports                = {}
        self.elephant_threshold_R   = None
        self.l_g_table              = {}
        self.flow_to_switches       = {}
        self.callback_table         = {}

    def exposed_send_report(self, flow):
        '''
        Remotely accessible function for switches to report flows to the Coordinator.
        This will be invoked from switches.

        Args:
            flow (tuple): The flow the switch reports
        '''

        self.handle_report(flow)


    def handle_report(self, flow):
        '''
        After receiving a report for a flow, the coordinator looks up its
        number of previous reports and depending whether the count exceeds
        the threshold, promotes it to a heavy hitter

        Args:
            flow (tuple): a 5 tuple identifying a flow
        '''

        flow_hash = self.flow_to_hash(flow)
        if flow_hash in self.reports:
            self.reports[flow_hash] += 1
        else:
            self.reports[flow_hash] = 1

        if self.reports[flow_hash] >= self.elephant_threshold_R:
            self.heavy_hitter_set.append(flow)

    def exposed_send_hello(self, flow, sw_name, hello_callback):
        '''
        Remotely accessible function for switches to report a flow it's never seen before.
        This will be invoked from switches.

        Args:
            flow (tuple):           The flow which the switch has newly seen and reports
            sw_name (str):          The name of the reporting switch
            hello_callback (func):  The callback function to send l_g back to switch. Callback
                                    fucntions will be stored.
        '''

        self.handle_hello(flow, sw_name, hello_callback)

    def handle_hello(self, flow, sw_name, hello_callback):
        '''
        Learning algorithm for l_g: Handles a hello message received from a switch
        Checks if the flow has already been seen for the reporting switch, updates the
        locality parameter if needed and sends locality parameter to switch(es)

        Args:
            flow (tuple):           The flow which the switch has newly seen and reports
            sw_name (str):          The name of the reporting switch
            hello_callback (func):  The callback function to send l_g back to switch. Callback
                                    functions will be stored. Callback function format is:
                                    callback(flow, l_g) (see L2Controller class)
        '''

        # store the callback
        if sw_name not in self.callback_table:
            self.callback_table[sw_name] = hello_callback

        flow_hash  = self.flow_to_hash(flow)
        group_hash = self.get_group_hash(flow)

        l_g = self.l_g_table[group_hash]

        if sw_name not in self.flow_to_switches[flow_hash]:
            self.flow_to_switches[flow_hash].append(sw_name)
            if len(self.flow_to_switches[flow]) >= 2*l_g:
                l_g = len(self.flow_to_switches[flow])
                self.l_g_table[group_hash] = l_g
                for switch in self.flow_to_switches[flow_hash]:
                    self.callback_table[switch](flow, l_g)
            else:
                self.callback_table[sw_name](flow, l_g)

    def extract_flow(self, msg):
        '''
        Extracts the flow information and the sw_name from the hello message
        sent by switch sw_name
        Assumes naming convention for switches: "s" + sw_identifier (int)

        Args:
            msg (): hello message from data plane through digest
        
        Returns:
            flow (tuple): a 5 tuple identifying a flow
            sw_name (str): the name of the switch originating the hello message
        '''

        #TODO: extract fields from digest

        return flow, sw_name

    def flow_to_hash(self, flow):
        '''
        Calculates a hash based on a flow tuple which is used to lookup
        the flow in the reports table

        Args:
            flow (tuple): a 5 tuple identifying a flow

        Returns:
            flow_hash (str): the hash identifying the flow
        '''

        #TODO: extract flow fields and calculate hash

        return flow_hash

    def get_group_hash(self, flow):
        '''
        Returns the hash of the group to which the flow belongs to

        Args:
            flow (tuple): Check to which group this flow belongs

        Returns:
            group_hash (str): the hash identifying the group
        '''

        #TODO: flow to group lookup, calculate hash

        return group_hash

class CoordinatorServer(object):
    '''
    The server running the Coordinator service
    '''

    def __init__(self, server_port=18812):
        self.server = ThreadedServer(CoordinatorService, port=server_port)

    def start(self):
        self.server.start()

    def stop(self):
        self.server.close()


if __name__ == '__main__':
    coordinator = CoordinatorServer()
    coordinator.start()