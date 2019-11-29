#!/bin/bash

lxterminal -e 'python ./controller/coordinator.py'
lxterminal -e 'sudo p4run --conf ./p4app/p4app_test.json'
sleep 20
python get_switch_names.py

cd controller

bash ../start_controllers.sh
