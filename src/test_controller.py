import time

from controller.controller import LocalController

if __name__ == '__main__':
    switch = LocalController('s1')

    while True:
        switch.report_flow('hello world')
        time.sleep(1)

