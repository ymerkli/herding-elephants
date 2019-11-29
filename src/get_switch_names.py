from p4utils.utils.topology import Topology

topo = Topology(db="topology.db")
f = open("active_switch_names.sh", "w+")
for p4switch in topo.get_p4switches():
    # starting all controllers in the same shell
    # start_controller = "sudo python l2_controller.py --n %s --t 1 --e 1 --s 1 &\n" % p4switch

    # starting controllers in different shells
    start_controller = "lxterminal -e 'sudo python l2_controller.py --n %s --t 1 --e 1 --s 1'\n" %p4switch
    f.write(start_controller)
f.close()
