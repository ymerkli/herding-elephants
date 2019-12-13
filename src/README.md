# Source Code

The source code roughly splits into three different parts:
1. P4 source code
2. Controllers
3. Helper scripts

## P4 source code
All the P4 source code is located in the folder `~/02-herding/src/p4src`. The P4 source code includes the following parts:

### Ingress switch (switch.p4)
This is the main P4 code where the Herd algorithm is implemented. `switch.p4` runs on ingress switches and does the sample-and-hold algorithm and the probabilistic reporting. An ingress switch sees packets belonging to some flow (based on the 5-tuple (srcIP, dstIP, srcPort, dstPort, protocol)). The locality of a flow is tracked based on its group. A group is defined as: (<first 8bits of srcIP>, <first 8bits of dstIP>). When a packet enters the ingress switch, it first checks if it has rules for the group of the flow in the group_values table. If not, a hello is sent to the controller, which will send a hello to the coordinator. If group values exist, the switch will check if it already samples the flow. If not, it will start sampling with probability *sampling_probability*. If the flow is already sampled, its counter in the multi-stage hash table will be increased. If the new counter reaches the mule threshold, the flow will be reported with probability *report_proability_g* (depends on the group) and the counter will be reset back to 0.

### Load balancer switch (load_balancing.p4)
This switch is needed for the evaluation. Each flow sent from the outside host will enter the network over two ingress switches. The ingress switch ID is determined based on a hash of the flow's source IP. The flow's packets are processed at a *preferred* ingress switch with probability *p = 0.95* and at a secondary ingress switch with probability *(1-p) = 0.05*. The load balancer basically just has a table with one rule for each ingress switch, matching on the ingress switch ID and forwarding the packet to the correct ingress switch, rewriting the source and destination MAC and the egress port.

### Aggregating switch (aggregating_switch.p4)
Once the packets have entered the network over the ingress switches, the ingress switches will send all packets to the aggregating switch which will just collect all packets and send them to a single host inside the network.

## Controllers
The controllers were all written in Python. We needed three different controllers and the coordinator.

### Coordinator
The coordinator is a centrally running server which has a global view over the ingress switches. Due to the need for asynchronous communication (hellos and reports can be sent at anytime), we implemented the communication model as a client-server remote procedure call (RPC) interaction. The coordinator is running a server which runs an coordinator service. This service implements two exposed functions: `send_hello` and `send_report`. These functions are called by the Herd Controllers when wanting to send hellos or reports.
For a hello, the coordinator needs to answer: the coordinator needs to answer with the group-based locality parameter l_g (how many switches see the group g). This is done via callback functions. When sending a hello, the Herd Controller also sends a callback function which is registered at the coordinator. The coordinator then calls the callback with l_g.
The coordinator keeps track of the number of reports that have been sent for each flow. Once the number of reports for a given flow reaches the reporting_threshold, the flow is promoted to an elephant (heavy-hitter). When the coordinator is terminated, a signal handler will write the found elephants to a json file.

### Herd Controller
Each ingress switch has an Herd Controller running. The Herd Controller receives hellos and reports from the data plane (through digests or copy-to-cpu), unpacks and processes them. Initially, the Herd Controller resets the controller state, passes the custom crc32 polynomials to the switch, writes the sampling probability in a register accessible by the data plane (this needs to be done from the control plane since there is no floating point arithmetic in P4) and fills a forwarding table which forwards packets to the aggregating switch.
The Herd Controller connect as clients to the coordinator server and send hellos and reports via the exposed functions `send_hello` and `send_report`. A hello is sent when the data plane sends a hello for a flow which hasnt been seen before. Once the Herd Controller receives the group-based locality parameter l_g via the callback from the coordinator, the Herd Controller calculates tau_g (the mule threshold for group g) and r_g (the probability that the switch sends a report for group g). These values are then written into the group_values table on the switch. A report is sent whenever the data plane sends a report.

### Load balancer/Aggregator controller
This controller only writes the forwarding rules for the load balancer switch and the aggregator switch. It basically writes rules mapping the ingress switch ID to the egress port pointing to the ingress switch and the interface MAC on the ingress switch.

## Helper scripts

### FlowEvaluator
This is a helper class that can compare two flow sets (json files), a real_elephant set (i.e. all flows in the respective pcap file which exceed a global threshold and are thus a heavy hitter) and a found_elephants (all flows that were classified as heavy hitters by Herd).

### Start_topology_and_eval
Bash script that starts a mininet for a given p4app and then starts evaluation runs

### Start_multiple_evaluation_runs
Python script that reads a csv file which specifies a parameter to run evaluations over (epsilon, sampling_probability) and then runs an evaluation run for each value of the given parameter specified in the csv file. The script automatically starts the coordinator, all Herd Controllers and the load balancer/ aggregator controller. It then logs into the outside host and sends packets from the specified pcap file, using tcpreplay. When sending is finished, the script shutsdown all controllers and the coordinator. It then reads the real and found elephants from json and calculates accuracy measures (f1 score, precision, recall) using FlowEvaluator.
