#!/bin/bash

lxterminal -e 'sudo p4run --conf ' $7 &
echo 'Starting mininet...'
sleep 30
echo 'Starting evaluation...'
python start_multiple_eval_runs.py --s $1 --e $2 --t $3 --r $4 --c $5 --p $6
