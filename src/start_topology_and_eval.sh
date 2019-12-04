#!/bin/bash

lxterminal -e 'sudo p4run --conf ' $6 &
sleep 30
python start_multiple_eval_runs.py --s $1 --e $2 --t $3 --r $4 --n $5 --p $7
