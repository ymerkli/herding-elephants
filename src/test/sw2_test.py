import time

from controller.l2_controller import L2Controller

sw2 = L2Controller('sw2')

sw2.send_hello('srcIP: 1.1.1.2, dstIP: 8.8.8.8')

time.sleep(2)

sw2.report_flow('srcIP: 1.1.1.2, dstIP: 8.8.8.8')

