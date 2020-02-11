# Hearding the Elephants: Detecting Network-Wide Heavy Hitters with Limited Resources

#### Authors
    * Yannick Merkli
    * Felix Ruessli
    * Tim Bohren

## Cloning the repository

```bash
git clone https://github.com/ymerkli/herding-elephants.git ~/
```

## Project description

Detecting heavy hitters (e.g. flows whose packet counts exceed a certain threshold) is an important task for Denial of Service detection, load balancing and traffic routing. Past work has shown how to detect heavy hitters on a single network switch. However, nowadays heavy hitter flows are often _network-wide_, thus detecting them on a single switch is not enough. A flow can enter a network over multiple ingress switches and from each switch's local view, the flow might look normal, whereas from a global view, the flow would be classified as a heavy hitter. Thus, a detection protocol should be distributed to detect flows from a global view and detection should still be quick and effective. Further, detecting global heavy-hitter flows inherently poses a trade-off between limitations in network-wide communication and memory resources on the ingress switches and accuracy in detecting heavy hitters. 

In this project, we have implemented Herd, a distributed algorithm which detects network-wide heavy hitters by combining probabilistic sample-and-hold with probabilistic reporting to a central coordinator.

Further an algorithm to tune Herd parameters in order to  maximize the  F1-score under communication and switch memory constraints is also implemented.


Herd introduces four different kind of flow categories: mice, moles, mules and elephants.

All flows start as mice. Mice flows are sampled randomly with sampling probability _s_ and promoted to moles. Mole flows are tracked by the switch: their packet counts are stored in a multi-stage hash table. Once a mole flow's packet count reaches the mule threshold  _τ_, the mole becomes a mule. Mules get reported to a central coordinator with report probability _r_. The coordinator counts how many times it received a report for each flow . Once the number of reports for a flow exceeds the report threshold _R_, the coordinator classifies the respective flow as an elephant.

In reality, flows exhibit preference for certain ingress switches, meaning  certain switches are more likely to observe certain flows. Due to this behaviour, we need to adapt the mule threshold _τ_ and the report probability _r_. Herd keeps track of locality by putting flows into groups _g(src, dst)_, where src and dst are /8 IP subnets. The coordinator keeps track of a locality parameter _l\_g_ for each group g. The mule threshold _τ\_g_ and the report probabiltiy _r\_g_ are then tracked on a per-group basis. 

The parameters _s_, _ε_ and _R_ can be calculated to maximize the F1 score under constraints on switch memory _S_ and the communication budget _C_ per switch. _ε_ is an approximation factor that is used to calculate the mule threshold _τ_.

## What did we reproduce
We were able to reproduce all parts of the Herd algorithm and the main parts of the evaluation of the Herd paper. Due to constraints on sending speed in the mininet, we were not able to test with large pcap files. Further, we were not able to reproduce the authors parameter tuning algorithm due to insufficient information from the paper.

## Repository organization
### src
Contains all source code including scripts for automated evaluation.
### report
Contains all latex files, figures and the report in pdf format.
### presentation
Contains the presentation in pptx format and a demo script.
### pcap
Contains pcap files used for the evaluation.
### parameters
Contains outputs from automated evaluation runs for parameter tuning
### evaluation
Contains various evaluation data

## How to test
For our evaluation, we've implemented an automated testing procedure which takes a set of parameters to evaluate over. For each parameter, a mininet will be started, the coordinator and all Herd Controllers (one per ingress switch in the given topology) will be started for the given parameters, the load balancer and aggregator switch will be
initialized and finally, all packets from the given pcap file will be sent from a host connected to the load balancer.

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
First, you have to decide over which parameter you want to sweep and which values of the parameter should be chosen. Currently supported parameters are: epsilon, sampling_probability (make sure to spell these correctly in the csv file). Create a .csv file in the following format:
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
* sampling probability: With which probability should an ingress switch sample a not yet tracked flow. Larger sampling proability leads to better performance (ess likely to miss a flow) but also more states on the switch.
* epsilon: The approximation factor epsilon. Epsilon is a tuning parameter and non-trivial to select right. A usual good choice is epsilon=l/k, where `l=number of ingress switches that see a flow` and `k=number of ingress switches`. For the usual case of `l=2` and `k=10`, `epsilon=0.2`.
* reporting threshold: After how many reports for a flow should the coordinator classify the flow as a heavy hitter. This parameter can be tuned and might be adapted to a specific pcap file. As a general rule, the paper specifies 1/epsilon.
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

### Run the controller
Run the herd controller on each ingress switch and pass the following parameters:
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
