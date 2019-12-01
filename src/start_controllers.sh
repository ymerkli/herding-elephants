cd controller
lxterminal -e 'python coordinator.py'
sleep 5
lxterminal -e 'sudo python l2_controller.py --n s3 --t 5 --e 1.0 --s 1.0'
lxterminal -e 'sudo python l2_controller.py --n s2 --t 5 --e 1.0 --s 1.0'
lxterminal -e 'sudo python l2_controller.py --n s1 --t 5 --e 1.0 --s 1.0'
cd ..
sleep 5
mx h1 python send.py --p ./data/first50.pcap --i 10.0.0.6