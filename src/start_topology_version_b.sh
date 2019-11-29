#!/bin/bash

lxterminal -e 'python ./controller/coordinator.py'
lxterminal -e 'sudo p4run --conf ./p4app/p4app_starting_controllers.json'
