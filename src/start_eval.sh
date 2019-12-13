#!/bin/bash

lxterminal -e 'sudo p4run --conf p4app/p4app_10_switches.json' &
echo 'Starting mininet...'
sleep 30
echo 'Starting evaluation...'
sudo python start_multiple_eval_runs.py --s 0.1 --e 0.2 --t 50 --r 11 --c ../evaluation/accuracy_epsilon/measurements_normal_100k.csv --p ../data/eval100k.pcap
echo "Sampling prob: $1, epsilon: $2, global_thresh: $3, reporting_tresh: $4, csv: $5 pcap: $6"

sleep 100

sudo python start_constrained_eval.py --t 50 --p ../data/eval100k.pcap --i ../parameters/constrained_comm/parameters_100k.csv --o ../evaluation/constrained_comm/measurements.csv
sleep 100
sudo python start_constrained_eval.py --t 50 --p ../data/eval100k.pcap --i ../parameters/constrained_state/parameters_100k.csv --o ../evaluation/constrained_state/measurements.csv
sleep 100

sudo python start_different_setups_eval.py --t 50 --s 0.1 --e 0.2 --p ../data/eval100k.pcap --f ../evaluation/accuracy_epsilon/measurements.csv --g ../evaluation/accuracy_epsilon/measurements_rla.csv
