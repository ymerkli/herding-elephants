lxterminal -e bash -c 'sudo python controller/coordinator.py --r 1; bash'
sleep 5
lxterminal -e bash -c 'sudo python controller/l2_controller.py --n lb1 --t 897 --e 0.2 --s 0.1'
lxterminal -e bash -c 'sudo python controller/l2_controller.py --n s1 --t 897 --e 0.2 --s 0.1'
lxterminal -e bash -c 'sudo python controller/l2_controller.py --n lb2 --t 897 --e 0.2 --s 0.1'
sleep 10
mx h1 python send.py --p ./data/dummmmy.pcap --i 10.0.0.6