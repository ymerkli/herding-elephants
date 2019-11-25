# Hearding the Elephants: Detecting Network-Wide Heavy Hitters with Limited Resources

#### Authors
    * Yannick Merkli    (ymerkli@student.ethz.ch)
    * Felix Ruessli     (fruessli@student.ethz.ch)
    * Tim Bohren        (tbohren@student.ethz.ch)

### Cloning the repository to VM

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

### How to test
## Run the p4app
```bash
sudo p4run --conf ~/02-herding/src/p4app/<p4app_name>.json
```

## Run the coordinator
IMPORTANT: the coordinator needs to be running before starting any l2_controller
```bash
python ~/02-herding/src/controllers/coordinator.py
```

## Run the L2 controller
Run the L2 controller on each switch and pass the following parameters:
* switch name: --s <switch_name>
* epsilon: --e <epsilon>
* global threshold: --t <global_threshold>
* sampling probability: --s <sampling_probability>

```bash
python ~/02-herding/src/controllers/l2_controller.py --s <switch_name> --e <epilon> --t <global_threshold> --s <sampling_probability>
```

## Send some traffic
Log into a host and send some traffic
```bash
mx <host_name>
python ~/02-herding/src/send.py
```

Brief project description
