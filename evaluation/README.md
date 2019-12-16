# Evaluation

## Evaluation results
This folder contains the evaluation results and should contain your evaluation results in case you start your own evaluation runs.

In the following, we explain the structure of this folder.

### data
In order to get the accuracy measures (F1 score, precision, recall), we need the "real elephants", i.e. the flows that actually are heavy hitters.

The 'data' folder already provides loads of json files we used for our evaluation. In case you want to use one of our pcap files, you can use our json files.

A quick explanation on files:

'global_thresholds.json' contains all global thresholds for percentiles 99, 99.9, 99.99 for various 'eval<packetcount>.pcap' files. Additionally, for each pcap file, the json states the number of flows (<pcap_file>_flow_count) and the number of groups (<pcap_file>_group_count) for various 'eval<packetcount>.pcap'.

'real_elephants_<num_packets>_<percentile>.json' contains all actual heavy hitters of pcap file '../data/eval<num_packets>.json' with a global threshold based on the percentile <percentile>

In case you want to use your own pcap files, you have to go through the following steps:

#### rewrite_mac.sh
Put your pcap file in the folder '~/02-herding/pcap'. In order to send the pcap file in the p4app mininet with 10 switches, you need to rewrite MAC addresses in the pcpa file. To do this, do the follwing steps:

'''bash
cd ~/02-herding/pcap
sudo bash rewrite_mac.sh <input_pcap_file> <output_pcap_file_name>
'''

#### global_threshold.py
'global_threshold.py' takes a pcap file and a percentile. The goal of 'global_threshold.py' is to determine a threshold on the packet count in order to separate small flows from heavy hitters. The global threshold returned is the provided percentile over all flow packet counts. Usual percentiles are 99, 99.9 and 99.99. The Herd paper uses the 99.99th percentile. For our evaluation we decided to use the 99th percentile since we had to use smaller pcap files, which results in only few
heavy hitter flows with the 99.99th percentile. 
Keep in mind that the smaller your pcap file, the fewer heavy hitter flows will exist with constant percentile.

How to run:
'''bash
sudo python global_threshold.py --p <pcap_file> --perc <percentile>
'''

#### real_elephants.py
'real_elephants.py' takes a pcap file, a global thereshold and the percentile used to get the global threshold. It then parses the pcap file and writes two json files: a 'real_count' json, which states the number of packets for each flow in the pcap file, and 'real_elephants' json, which lists all flows which are elephant (heavy hiter) flows, i.e. all flows whose packet counts exceed the global threshold.

How to run:
'''bash
sudo python real_elephants.py --p <pcap_file> --t <global_threshold> --perc <percentile_used_for_global_threshold>
'''

## Start your own evaluation
Evaluations are started from the src folder.
'''bash
cd ~/02-herding/src
'''

### FlowEvaluator
This is a helper class that can compare two flow sets (json files), a real_elephant set (i.e. all flows in the respective pcap file which exceed a global threshold and are thus a heavy hitter) and a found_elephants (all flows that were classified as heavy hitters by Herd).

### Start_topology_and_eval
Bash script that starts a mininet for a given p4app and then starts evaluation runs.
In order to start an evaluation run, you need to define a .csv file which defines the parameter over which the evalutations should run. The structure of the .csv file should look as follows:

'''
<parameter_name>,f1score,precsion,recall
parameter_value_1,
parameter_value_2,
parameter_value_3,
.
.
.
'''

Supported parameter_names are: 'epsilon', 'sampling_probability'.

The evaluation parameters are then passed as follows:

'''bash
sudo bash start_topology_and_eval.sh <sampling_probability> <epsilon> <gobal_threshold> <report_threshold> <csv_file> <pcap_file> <p4app_file>
'''

### Start_multiple_evaluation_runs
Python script that reads a csv file which specifies a parameter to run evaluations over (epsilon, sampling_probability) and then runs an evaluation run for each value of the given parameter specified in the csv file. The script automatically starts the coordinator, all L2Controllers and the load balancer/ aggregator controller. It then logs into the outside host and sends packets from the specified pcap file, using tcpreplay. When sending is finished, the script shutsdown all controllers and the coordinator. It then reads the real and found elephants from json and calculates accuracy measures (f1 score, precision, recall) using FlowEvaluator.

