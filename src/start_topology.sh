#!/bin/bash

lxterminal -e 'sudo p4run --conf ./p4app/p4app_simple.json' &
sleep 15
python restart_controllers.py --r 1 --s 0.1 --t 897 --e 0.2 --p $1
