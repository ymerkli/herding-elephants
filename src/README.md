# Source Code

The source code roughly splits into three different parts:
1. P4 source code
2. Controllers
3. Helper scripts

## P4 source code
All the P4 source code is located in the folder `~/02-herding/src/p4src`. The P4 source code includes the following parts:

### switch.p4 (Ingress switch)
This is the main P4 code where the Herd algorithm is implemented. `switch.p4` runs on ingress switches and does the sample-and-hold algorithm and the probabilistic reporting. An ingress switch sees packets belonging to some flow (based on the 5-tuple (srcIP, dstIP, srcPort, dstPort, protocol)). The locality of a flow is tracked based on its group. A group is defined as: (<first 8bits of srcIP>, <first 8bits of dstIP>). When a apcket enters the ingress switch, it first checks if it has rules for the group of the flow in the group_values table. If not, a hello is sent to the controller, which will send a hello to the coordinator. If group values exist, the switch will check if it already samples the flow. If not, it will start sampling with probability *sampling_probability*. If the flow is already sampled, its counter in the multi-stage hash table will be increased. If the new counter reaches the mule threshold, the flow will be reported with probability *report_proability_g* (depends on the group) and the counter will be reset back to 0.

### load_balancing.p4 (load balancer switch)
This switch is needed for the evaluation. Each flow will enter the network over two ingress switches. The ingress switch ID is determined based on a hash of the flow's source IP. The flow's packets are processed at a *preferred* ingress switch with probability *p = 0.95* and at a secondary ingress switch with probability *(1-p) = 0.05*. The load balancer basically just has a table with one rule for each ingress switch, matching on the ingress switch ID and forwarding the packet to the correct ingress switch, rewriting the source and destination MAC and the egress port.

### aggregating_switch.p4 (aggregating switch)
Once the packets have entered the network over the ingress switches, the ingress switches will send all packets to the aggregating switch which will just collect all packets and send them to a single host inside the network.

## Controllers
The 