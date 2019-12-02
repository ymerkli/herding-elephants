#!/bin/bash

lxterminal -e 'sudo p4run --conf ./p4app/p4app_10_switches.json' &
sleep 25
python restart_controllers.py --r 1 --s 1 --t 5 --e 1 --p $1 
