import socket
import struct
import pickle
import os
import rpyc
import nnpy

from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
#from crc import Crc
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
                                    to which the flow belongs to. Key is a flow table, value is an int
        flow_to_switches (dict):    A dict storing which switches have seen a flow. Key is a flow tuple, value is an array
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

        # if the flow has been reported before, increase its count
        # otherwise, start counting
        if flow in self.reports:
            self.reports[flow] += 1
        else:
            self.reports[flow] = 1

        # if the number of reports reaches the report threshold, we have a heavy hitter
        if self.reports[flow] >= self.elephant_threshold_R:
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

        print(flow, sw_name)
        # store the callback function since we need it several times
        if sw_name not in self.callback_table:
            self.callback_table[sw_name] = hello_callback

        # lookup the group based locality parameter l_g
        # initialize l_g to 1 if no switch has seen the flow yet
        if flow not in self.l_g_table:
            self.l_g_table[flow] = 1
        l_g = self.l_g_table[flow]

        # initialize flow_to_switch array if no switch has seen the flow yet
        if flow not in self.flow_to_switches:
            self.flow_to_switches[flow] = []

        # check if the switch has already sent a hello for this flow
        if sw_name not in self.flow_to_switches[flow]:
            # remember that switch sw_name has seen flow
            self.flow_to_switches[flow].append(sw_name)
            if len(self.flow_to_switches[flow]) >= 2*l_g:
                # localitiy parameter has changed significantly
                l_g = len(self.flow_to_switches[flow])
                self.l_g_table[flow] = l_g
                # send it to all switches that have seen flow
                for switch in self.flow_to_switches[flow]:
                    self.callback_table[switch](flow, l_g)
            else:
                # only send locality parameter to sw_name
                self.callback_table[sw_name](flow, l_g)

class CoordinatorServer(object):
    '''
    The server running the Coordinator service

    Args:
        server_port (int):  The port on which the Coordinator will be running on
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