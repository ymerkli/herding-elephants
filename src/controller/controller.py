import socket
import struct
import pickle
import os
import rpyc

#from p4utils.utils.topology import Topology
#from p4utils.utils.sswitch_API import *
#from crc import Crc
from rpyc.utils.server import ThreadedServer

class CoordinatorService(rpyc.Service):
    '''
    Rpyc service that receives messages from switch controllers
    '''

    def exposed_echo(self, text):
        print(text)

class Coordinator(object):
    '''
    The Coordinator object is a centrally running Controller that aggregates
    partial information observed at each switch to identify network-wide elephants.
    The switches send messages to the Coordinator

    Args:

    Attributes:
        heavy_hitter_set (dict): A dict of flows which are heavy hitters. Key is the flow hash
        reports (dict): A dict of flows and their report count. Key is the flow hash
        reporting_threshold (int): The number of thresholds for which we promote a flow to a heavy hitter
    '''

    def __init__(self):
        self.heavy_hitter_set       = {}
        self.reports                = {}
        self.reporting_threshold    = None
        self.server                 = ThreadedServer(CoordinatorService, port=18812)

        self.server.start()

        print('server started')

    def coordinator_algorithm(flow):
        '''
        After receiving a report for a flow, the coordinator looks up its
        number of previous reports and depending whether the count exceeds
        the threshold, promotes it to a heavy hitter

        Args:
            flow (tuple): a 5 tuple identifying a flow
        '''
        flow_hash = flow_to_hash(flow)
        if flow_hash in self.reports:
            self.reports[flow_hash] += 1
        else:
            self.reports[flow_hash] = 1

        if self.reports[flow_hash] >= self.reporting_threshold:
            self.heavy_hitter_set.append(flow)

    def flow_to_hash(flow):
        '''
        Calculates a hash based on a flow tuple which is used to lookup
        the flow in the reports table

        Args:
            flow (tuple): a 5 tuple identifying a flow

        Returns:
            flow_hash (str): the hash identifying the flow
        '''




class LocalController(object):
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

        #self.topo    = Topology(db="topology.db")
        self.sw_name = sw_name
        #self.thrift_port = self.topo.get_thrift_port(sw_name)
        #self.controller = SimpleSwitchAPI(self.thrift_port)

        self.coordinator_c = rpyc.connect('localhost', 18812)

    def report_flow(self, msg):
        '''
        Reports a flow to the central coordinator
        '''

        self.coordinator_c.root.echo(msg)

