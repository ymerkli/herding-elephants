# Evaluation

## Evaluation results
This folder contains our evaluation results and should contain your evaluation results in case you start your own evaluation runs.

In the following, we explain the structure of this folder.

### data
In order to get the accuracy measures (F1 score, precision, recall), we need the "real elephants", i.e. the flows that actually are heavy hitters.

The `data` folder already provides loads of json files which we used for our evaluation. In case you want to use one of our pcap files (located in `~/02.herding/pcap/`), you can use our json files.

A quick explanation on files:

`global_thresholds.json` contains all global thresholds for percentiles 99, 99.9, 99.99 for various `eval<num_packets>.pcap` files. Additionally, for each pcap file, the json states the number of flows (<pcap_file>_flow_count) and the number of groups (<pcap_file>_group_count) for various `eval<num_packets>.pcap`.

`real_elephants_<num_packets>_<percentile>.json` contains all actual heavy hitters of pcap file `~/02-herding/pcap/eval<num_packets>.json` with a global threshold based on the percentile <percentile>

In case you want to use your own pcap files, you have to go through the following steps:

#### rewrite_mac.sh
Put your pcap file in the folder `~/02-herding/pcap`. In order to send the pcap file in the p4app mininet with 10 switches, you need to rewrite MAC addresses in the pcpa file. To do this, execute the following command:

```bash
cd ~/02-herding/pcap
sudo bash rewrite_mac.sh <input_pcap_file> <output_pcap_file_name>
```

NOTE: this script assumes that you use the `~/02-herding/src/p4app/p4app_10_switches.json` (the MAC to be written depend on the p4app)

#### global_threshold.py
`global_threshold.py` takes a pcap file and a percentile. The goal of `global_threshold.py` is to determine a threshold on the packet count in order to separate small flows from heavy hitters. The global threshold returned is the provided percentile over all flow packet counts. Usual percentiles are 99, 99.9 and 99.99. The Herd paper uses the 99.99th percentile. For our evaluation we decided to use the 99th percentile since we had to use smaller pcap files, which results in only few
heavy hitter flows with the 99.99th percentile.
Keep in mind that the smaller your pcap file, the fewer heavy hitter flows will exist with constant percentile.

How to run:
```bash
sudo python global_threshold.py --p <pcap_file> --perc <percentile>
```

#### real_elephants.py
`real_elephants.py` takes a pcap file, a global thereshold and the percentile used to get the global threshold. It then parses the pcap file and writes two json files: a `real_count` json, which states the number of packets for each flow in the pcap file, and `real_elephants` json, which lists all flows which are elephant (heavy hitter) flows, i.e. all flows whose packet counts exceed the global threshold.

How to run:
```bash
sudo python real_elephants.py --p <pcap_file> --t <global_threshold> --perc <percentile_used_for_global_threshold>
```

## Start an evaluation
Evaluations are started from the src folder.
```bash
cd ~/02-herding/src
```

### Scripts
#### Start_topology_and_eval
Bash script that starts a mininet for a given p4app and then starts evaluation runs.
In order to start an evaluation run, you need to define a .csv file which defines the parameter over which the evalutations should run. The structure of the .csv file should look as follows:

```
<parameter_name>,f1score,precsion,recall
parameter_value_1,
parameter_value_2,
parameter_value_3,
.
.
.
```

Supported parameter_names are: `epsilon`, `sampling_probability`.

Put your custom csv file in a folder inside `~/02-herding/evaluation`.


The evaluation parameters are then passed as follows:

```bash
sudo bash start_topology_and_eval.sh <sampling_probability> <epsilon> <gobal_threshold> <report_threshold> <csv_file> <pcap_file> <p4app_file>
```

#### start_multiple_evaluation_runs
Python script that reads a csv file which specifies a parameter to run evaluations over (epsilon, sampling_probability) and then runs an evaluation run for each value of the given parameter specified in the csv file. The script automatically starts the coordinator, all L2Controllers and the load balancer/ aggregator controller. It then logs into the outside host and sends packets from the specified pcap file, using tcpreplay. When sending is finished, the script shutsdown all controllers and the coordinator. It then reads the real and found elephants from json and calculates accuracy measures (f1 score, precision, recall) using FlowEvaluator. Finally,

### I don't want to read all of this...
#### I want a quick evaluation to see how automated evaluation works (2 minutes)
For a quick test evaluation which won't take much time, run the following command:
```bash
sudo bash start_topology_and_eval.sh 1.0 0.1 11 5 ~/02-herding/evaluation/basic/measurements_layout.csv ~/02-herding/pcap/eval500.pcap ~/02-herding/src/p4app/p4app_10_switches_herd.json
```
This will run three evaluation rounds (3 different epsilon values) with 500 packets each.
NOTE: this evaluation is not representative since the pcap file consists of only 500 packets.

#### I want to run a real evaluation and reproduce our results (8 hours)
For a serious evaluation (the ones we did), run one of the following command:

Evaluate over epsilon:
```bash
sudo bash start_topology_and_eval.sh 0.2 0.1 91 10 ~/02-herding/evaluation/accuracy_epsilon/epsilon_layout.csv ~/02-herding/pcap/eval400k.pcap ~/02-herding/src/p4app/p4app_10_switches_herd.json
```
Evaluate over sampling probabilities:
```bash
sudo bash start_topology_and_eval.sh 0.2 0.1 91 10 ~/02-herding/evaluation/accuracy_sampling_prob/sampl_prob_layout.csv ~/02-herding/pcap/eval400k.pcap ~/02-herding/src/p4app/p4app_10_switches_herd.json
```

### Automated testing

#### 1. Define a measurements script
First, you have to decide over which parameter you want to sweep and which values of the parameter should be chosen. Supported parameters are: epsilon, sampling_probability (make sure to spell these correctly in the csv file). Create a .csv file in the following format:
```
<parameter_name>,f1score,precision,recall
<parameter_value_1>
<parameter_value_2>
...
<parameter_value_n>
```
There already exists a basic evaluation file in `~/02-herding/evaluation/basic/measurements.csv` which can be used.

#### 2. Decide on parameter values
The following values need to be specified to start an evaluation run:
* global_threshold: The number of packets for which a flow is considered a heavy hitter. This needs to be determined using the `global_threshold.py` script. The global threshold is usually the 99th percentile on the packet count over all flows. For the given pcap files, the global_thresholds are specified in `~/02-herding/evaluation/data/global_thresholds.json`.
* sampling probability: With which probability should an ingress switch sample a not yet tracked flow.
* epsilon: The approximation factor epsilon. Epsilon is a tuning parameter and non-trivial to select. A usual good choice is epsilon=l/k, where `l=number of ingress switches that see a flow` and `k=number of ingress switches`. For the usual case of `l=2` and `k=10`, `epsilon=0.2`. In our evaluation, we found `epsilon=0.09` to be optimal.
* reporting threshold: After how many reports for a flow should the coordinator classify the flow as a heavy hitter. This parameter can be tuned and might be adapted to a specific pcap file. As a general rule, the paper specifies `R = 1/epsilon`. Idealy, selecting `R` would be done via joint parameter tuning, however as stated in our report, we were not able to reproduce this.
* pcap file: The path to the pcap file which should be sent from the host.
* csv file: The path to the csv file where the parameter values to evaluate over are taken from and f1score, precision, recall will be written to.

NOTE: The parameter you want to sweep over still needs to be initialized to some value, but this value will be ignored.

#### 3. Start an evaluation run
An evaluation run is started using the script `start_topology_and_eval.sh` as follows:
```bash
sudo bash start_topology_and_eval.sh <sampling_prob> <epsilon> <global_threshold> <reporting_threshold> <csv_file_path> <pcap_file_path> <p4app_file_path>
```

`start_topology_and_eval.sh` will start a mininet for the given p4app and then start the evaluation runs.

NOTE: During our evaluation, we've encountered dropped packets at the load balancer at around 8000 packets per second and dropped hellos and reports between ingress switch and local controller at around 400 packets per second. The limiting factor seemed to be the communication between data plane and controll plane and the time delay between sending a hello to the central coordinator and receiving a hello callback and then adding rules to the switch table. Due to this, we had to test at rather low sending speeds (300 packets per second). That's why evaluation takes rather long and the pcap files are rather short.


#### 4. Check the results
After all evaluation rounds have finished, check your csv file. For each evalution round, you will find the f1score, precision and recall.
These accuracy measures are calculated using `~/02-herding/evaluation/data/real_elephants_...`. These json files list all flows for the specific pcap files which are heavy hitters (i.e. the packet count for the flow exceeds the global threshold).

### Manual run

#### Start the mininet
```bash
sudo p4run --conf ~/02-herding/src/p4app/<p4app_name>.json
```
### Run the coordinator
IMPORTANT: the coordinator needs to be running before starting any l2_controller
```bash
python ~/02-herding/src/controllers/coordinator.py --r <reporting_threshold> --v
```

### Run the L2 controller
Run the L2 controller on each ingress switch and pass the following parameters:
* switch name: --n <switch_name>
* epsilon: --e <epsilon>
* global threshold: --t <global_threshold>
* sampling probability: --s <sampling_probability>

```bash
python ~/02-herding/src/controllers/l2_controller.py --s <switch_name> --e <epilon> --t <global_threshold> --s <sampling_probability>
```

### Send some traffic
Log into a host and send some traffic. Due to aforemention issues with sending speed, keep the sending speed below 300pps.
```bash
mx <host_name>
sudo tcpreplay -i <host_name>-eth0 -p 300 <pcap_file_path>
```
