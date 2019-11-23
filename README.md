# Herding the Elephants
#### Authors
    * Yannick Merkli    (ymerkli@student.ethz.ch)
    * Felix Ruessli     (fruessli@student.ethz.ch)
    * Tim Bohren        (tbohren@student.ethz.ch)

### Cloning the repository to VM

```bash
cd/home/p4
git clone https://gitlab.ethz.ch/nsg/adv-comm-net-projects/02-herding.git
```

### Update local repository

```bash
cd /home/p4/02-herding
git pull https://gitlab.ethz.ch/nsg/adv-comm-net-projects/02-herding.git
```

### Commit and push
```bash
cd /home/p4/02-herding
git add filename.txt
git commit -m "YourMessage"
git remote add origin https://gitlab.ethz.ch/nsg/adv-comm-net-projects/02-herding.git
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