# Hearding the Elephants: Detecting Network-Wide Heavy Hitters with Limited Resources

#### Authors
    * Yannick Merkli    (ymerkli@student.ethz.ch)
    * Felix Ruessli     (fruessli@student.ethz.ch)
    * Tim Bohren        (tbohren@student.ethz.ch)

## Cloning the repository

```bash
git clone https://gitlab.ethz.ch/nsg/adv-comm-net-projects/02-herding.git ~/
```

### Update local repository

```bash
git pull https://gitlab.ethz.ch/nsg/adv-comm-net-projects/02-herding.git
```

### Commit and push
```bash
cd /home/p4/02-herding
git add filename.txt
git commit -m "YourMessage"
git push -u origin master
```

### Commit and push to branch
```bash
cd /home/p4/02-herding
git add filename.txt
git commit -m "YourMessage"
git push -u origin branchname
```

#### Brief project description
Herd is distributed algorithm which detects network-wide heavy hitters by combining sample-and-hold with probabilistic reporting to a central coordinator.
Further an algorithm to tune Herd for a maximum F1-score under communication and state constraints is also implemented.

We have four different kind of categories for flow: mice, moles, mules and elephants.

All flows start as mice. Mice flows get picked randomly with probability _s_ and promoted to mules. Moles get tracked by the switch how often they appear. Once the moles reach a certain size, meaning they were seen on the switch _τ_ times, the moles become mules. The mules get reported to a central coordinator with the probability _r_. The coordinator counts from now on how many times it receives a report from a switch of that mules flow. Once it received _R_ reports it classifies that report as an elephant.

The parameters _s_, _τ_, _r_ and _R_ can be calculated to maximize the F1-score under the constraints of limited switch memory _S_ and a maximum communication budget per switch. In order to calculate _τ_ we use an approximation factor _ε_.
We do this by more or less with a try and error approach.
## How to test
### Run the p4app
```bash
sudo p4run --conf ~/02-herding/src/p4app/<p4app_name>.json
```

### Run the coordinator
IMPORTANT: the coordinator needs to be running before starting any l2_controller
```bash
python ~/02-herding/src/controllers/coordinator.py
```

### Run the L2 controller
Run the L2 controller on each switch and pass the following parameters:
* switch name: --s <switch_name>
* epsilon: --e <epsilon>
* global threshold: --t <global_threshold>
* sampling probability: --s <sampling_probability>

```bash
python ~/02-herding/src/controllers/l2_controller.py --s <switch_name> --e <epilon> --t <global_threshold> --s <sampling_probability>
```

### Send some traffic
Log into a host and send some traffic
```bash
mx <host_name>
python ~/02-herding/src/send.py
```

### Start mininet and send traffic
* Topology can be changed by editing the first cmd
* Controllers are started by the restart_controllers.py skript with the given parameters
* Pcap file is used later to generate traffic

After startup of the mininet, coordinator and controllers, h1 executes send.py 
which uses the given pcap file to simulate traffic.

```bash
bash start_topology.sh
```

Brief project description
