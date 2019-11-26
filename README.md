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

We have four different kind of categories for flow: mice, moles, mules and elephants.

All flows start as mice. Mice flows get picked randomly with probability _s_** and promoted to mules. Moles get tracked by the switch how often they appear. Once the moles reach a certain size, meaning they were seen on the switch _τ_** times, the moles become mules. The mules get reported to a central coordinator with the probability _r_**. The coordinator counts from now on how many times it receives a report from a switch of that mules flow. Once it received _R_** reports it classifies that report as an elephant.

The parameters _s_, _τ_, _r_ and _R_ can be calculated to maximize the F1-score under the constraints of limited switch memory _S_** and a maximum communication budget per switch. In order to calculate _τ_ we use an approximation factor _ε_**.
We do this by more or less with a try and error approach.
