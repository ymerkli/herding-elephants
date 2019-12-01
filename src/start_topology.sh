#!/bin/bash

lxterminal -e 'sudo p4run --conf ./p4app/p4app.json' &
sleep 20
python restart_controllers.py --s 1 --t 5 --e 1 --p "./data/first5.pcap"
