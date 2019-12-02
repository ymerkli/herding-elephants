lxterminal -e bash -c 'sudo python controller/coordinator.py; bash'
sleep 5
lxterminal -e bash -c 'sudo python controller/l2_controller.py --n s3 --t 5 --e 1.0 --s 1.0; bash'
lxterminal -e bash -c 'sudo python controller/l2_controller.py --n s2 --t 5 --e 1.0 --s 1.0; bash'
lxterminal -e bash -c 'sudo python controller/l2_controller.py --n s1 --t 5 --e 1.0 --s 1.0; bash'
sleep 5
mx h1 python send.py --p ./data/first5.pcap --i 10.0.0.6