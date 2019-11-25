import time

from l2_controller import L2Controller

sw2 = L2Controller('s2', 1, 1, 1)

sw2.send_hello('srcIP: 1.1.1.2, dstIP: 8.8.8.8')

time.sleep(2)

sw2.report_flow('srcIP: 1.1.1.2, dstIP: 8.8.8.8')
