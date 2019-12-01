#!/bin/bash

lxterminal -e 'sudo p4run --conf ./p4app/p4app_generated.json' &
sleep 20
python restart_controllers.py --s 1 --t 5 --e 1 --p "./data/first50.pcap"
