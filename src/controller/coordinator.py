import socket
import struct
import pickle
import os
import rpyc
import nnpy
import json
import signal
import argparse
import sys
import time
import gc; gc.disable()

from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
from rpyc.utils.server import ThreadedServer
from scapy.all import Ether, sniff, Packet, BitField


class CoordinatorService(rpyc.Service):
    '''
    The CoordinatorService object is the service running on the Coordinator that aggregates
    partial information observed at each switch to identify network-wide elephants.
    The switches send messages to the Coordinator

    Args:
        reporting_threshold_R (int): The thresholds on the report count for which we promote a mule to a heavy hitter
        output_file_path (str):         The filepath where the found heavy hitters (elephants) will be written to json file
        verbose (bool):                 Whether Coordinator should run in verbose mode (write what's happening to stdout)

    Attributes:
        heavy_hitter_set (list):        A list of flows which are heavy hitters
        reports (dict):                 A dict of flows and their report count. Key is the flow hash
        reporting_threshold_R (int):    The thresholds on the report count for which we promote a mule to a heavy hitter
        l_g_table (dict):               A dict storing the locality parameter l_g for a flow based on the group (2-tuple)
                                        to which the flow belongs to. Key is a group, value is an int
        group_to_switches (dict):       A dict storing which switches have seen a flow. Key is a group (2-tuple), 
                                        value is an array of sw_names
        callback_table (dict):          A dict storing the callbacks received from switches in hello messages.
                                        Callbacks are used to send l_g back to switches. Key is a sw_name (str), value is a function.
        output_file_path (str):         The filepath where the found heavy hitters (elephants) will be written to json file
        received_hellos (int):          The number of hellos the coordinator has received from all switches
        received_reports (int):         The number of reports the coordinator has received from all switches
        verbose (bool):                 Whether Coordinator runs in verbose mode (write what's happening to stdout)
    '''

    def __init__(self, reporting_threshold_R, output_file_path, verbose):
        self.heavy_hitter_set       = []
        self.reports                = {}
        self.reporting_threshold_R  = reporting_threshold_R
        self.l_g_table              = {}
        self.group_to_switches      = {}
        self.callback_table         = {}
        self.output_file_path       = output_file_path
        self.received_hellos        = 0
        self.received_reports       = 0
        self.verbose                = verbose

    def exposed_send_report(self, flow, sw_name):
        '''
        Remotely accessible function for switches to report flows to the Coordinator.
        This will be invoked from switches.

        Args:
            flow (tuple):   The flow the switch reports
            sw_name (str):  The name of the switch that sent the report
        '''

        self.received_reports += 1
        self.handle_report(flow, sw_name)


    def handle_report(self, flow, sw_name):
        '''
        After receiving a report for a flow, the coordinator looks up its
        number of previous reports and depending whether the count exceeds
        the threshold, promotes it to a heavy hitter

        Args:
            flow (tuple):   The flow the switch reports
            sw_name (str):  The name of the switch that sent the report
        '''

        if self.verbose:
            print("Received report from {0} for {1}".format(sw_name, flow))

        # if the flow has been reported before, increase its count
        # otherwise, start counting
        if flow in self.reports:
            self.reports[flow] += 1
        else:
            self.reports[flow] = 1

        # if the number of reports reaches the report threshold, we have a heavy hitter
        if str(flow) not in self.heavy_hitter_set and self.reports[flow] >= self.reporting_threshold_R:
            self.heavy_hitter_set.append(str(flow))

    def exposed_send_hello(self, flow, sw_name, hello_callback):
        '''
        Remotely accessible function for switches to report a flow it's never seen before.
        This will be invoked from switches.

        Args:
            flow (tuple):           The flow which the switch has newly seen and reports
            sw_name (str):          The name of the reporting switch
            hello_callback (func):  The callback function to send l_g back to switch. Callback
                                    functions will be stored.
        '''

        self.received_hellos += 1
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

        if self.verbose:
            print("Received hello from {0} for {1}".format(sw_name, flow))

        # store the callback function since we need it several times
        if sw_name not in self.callback_table:
            self.callback_table[sw_name] = hello_callback

        srcGroup, dstGroup = self.extract_group(flow)
        group = (srcGroup, dstGroup)

        # lookup the group based locality parameter l_g
        # initialize l_g to 1 if no switch has seen the group yet
        if group not in self.l_g_table:
            self.l_g_table[group] = 1
        l_g = self.l_g_table[group]

        # initialize grouo_to_switch array if no switch has seen the group yet
        if group not in self.group_to_switches:
            self.group_to_switches[group] = []

        # check if the switch has already sent a hello for this group
        if sw_name not in self.group_to_switches[group]:
            # remember that switch sw_name has seen group
            self.group_to_switches[group].append(sw_name)
            if len(self.group_to_switches[group]) >= 2*l_g:
                # localitiy parameter has changed significantly
                l_g = len(self.group_to_switches[group])
                self.l_g_table[group] = l_g
                # send it to all switches that have seen group
                for switch in self.group_to_switches[group]:
                    self.callback_table[switch](flow, l_g)
            else:
                # only send locality parameter to sw_name
                self.callback_table[sw_name](flow, l_g)

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

    def heavy_hitter_to_json(self):
        '''
        Writes all the found elephant flows to JSON

        Args:
            output_file_path (str): The file path where the JSON will be written to
        '''

        data = {
            'found_elephants': self.heavy_hitter_set
        }

        with open(self.output_file_path, 'w+') as outfile:
            json.dump(data, outfile, indent=4)
            outfile.close()

        print("Detected {0} heavy hitter flows".format(len(self.heavy_hitter_set)))
        print("Wrote found heavy hitter to {0}".format(self.output_file_path))
        print("Coordinator received {0} hellos, {1} reports".format(self.received_hellos, self.received_reports))

class CoordinatorServer(object):
    '''
    The server running the Coordinator service

    Args:
        server_port (int):                  The port on which the Coordinator will be running on
        reporting_threshold_R (int):        The thresholds on the report count for which we promote a mule to a heavy hitter
        output_file_path (str):             The file path where the heavy hitter set will be written to
        verbose (bool):                     Whether Coordinator should run in verbose mode (write what's happening to stdout)
    Attributes:
        coordinator_service (rpyc service): The rpyc service which runs on the coordinator server
        server (rpyc threaded server):      The rpyc server (running in threaded mode) which runs the service
    '''

    def __init__(self, server_port, reporting_threshold_R, output_file_path, verbose):
        self.coordinator_service = CoordinatorService(reporting_threshold_R, output_file_path, verbose)
        self.server              = ThreadedServer(self.coordinator_service, port=server_port)

    def start(self):
        '''
        Starts the Coordinator server
        '''
        print("Starting Coordinator")
        self.server.start()

    def stop(self):
        '''
        Stops the Coordinator server
        '''
        self.server.close()

    def signal_handler(self, sig, frame):
        '''
        Writes the heavy hitter set to JSON and stops the Coordinator server upon SIGINT
        '''
        self.coordinator_service.heavy_hitter_to_json()
        self.stop()
        print('ByeBye')
        sys.exit(0)

def parser():
    parser = argparse.ArgumentParser(description='parse the keyword arguments')

    parser.add_argument(
        "--p",
        type=int,
        required=False,
        default=18812,
        help="The port on which the coordinator should run on"
    )

    parser.add_argument(
        "--r",
        type=int,
        required=True,
        help="The reporting threshold for which we promote a mule to a heavy hitter"
    )

    parser.add_argument(
        "--o",
        type=str,
        required=False,
        default='../evaluation/data/found_elephants.json',
        help="The output path for the heavy hitter set"
    )

    parser.add_argument(
        "--v",
        action="store_true"
    )

    args = parser.parse_args()

    return args.p, args.r, args.o, args.v

if __name__ == '__main__':

    coordinator_server_port, reporting_threshold_R, output_file_path, verbose = parser()

    # error checking
    if reporting_threshold_R < 1:
        raise ValueError("Error: invalid reporting threshold, must be >= 1: {0}".format(
            reporting_threshold_R
        ))

    coordinator = CoordinatorServer(coordinator_server_port, reporting_threshold_R, output_file_path, verbose)

    # register signal handler to handle shutdowns
    signal.signal(signal.SIGINT, coordinator.signal_handler)

    #sys.tracebacklimit = 0

    # start the coordinator
    try:
        coordinator.start()
    except AssertionError:
        pass
