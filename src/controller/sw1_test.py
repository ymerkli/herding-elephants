import time

from l2_controller import L2Controller

sw1 = L2Controller('s1', 1, 1)

sw1.send_hello('srcIP: 1.1.1.1, dstIP: 8.8.8.8')

time.sleep(2)

#sw1.report_flow('srcIP: 1.1.1.1, dstIP: 8.8.8.8')

