import argparse
import subprocess


# if get_com_budget_params.py gets run as script
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description = 'parse the keyword arguments')

    parser.add_argument(
        '--lb',
        required = True,
        type = int,
        help = 'Lower bound for communication budget'
    )

    parser.add_argument(
        '--ub',
        type = int,
        required = True,
        help = 'Upper bound for communication budget'
    )

    parser.add_argument(
        '--p',
        required = True,
        help = 'Path to .pcap file'
    )

    parser.add_argument(
        '--t',
        type = int,
        required = True,
        help = 'global threshold'
    )
    args = parser.parse_args()

    comm_budget = args.lb
    while (comm_budget <= args.ub):
        subprocess.call(['python', 'tuningparameters0.py', '--p', '%s' % args.p, '--t', '%s' % args.t, '--c', '%s' % comm_budget, '--s', '500000'])
        comm_budget = comm_budget + 500
