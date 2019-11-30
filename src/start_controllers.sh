cd controller
lxterminal -e 'python coordinator.py'
lxterminal -e 'sudo python l2_controller.py --n s2 --t 1 --e 1.0 --s 1.0'
lxterminal -e 'sudo python l2_controller.py --n s1 --t 1 --e 1.0 --s 1.0'
cd ..
sleep 5
mx h1 python send_one_message.py 10.0.0.4 boop