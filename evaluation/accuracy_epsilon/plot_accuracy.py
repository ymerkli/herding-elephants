import argparse
import matplotlib.pyplot as plt
import csv
import os
import math

def parser():
    parser = argparse.ArgumentParser(description='parse the keyword arguments')

    parser.add_argument(
            "--c",
            type=str,
            required=True,
            help="The path to the csv file to plot"
    )

    parser.add_argument(
            "--o",
            type=str,
            required=True,
            help="The output file path for the figure"
    )

    args = parser.parse_args()

    return args.c, args.o

def read_csv(csv_file_path):
    '''
    Reads the measurements from csv file
    The format of the csv file needs to be:
        <parameter_name>,f1score,precision,recall
        1,
        2, 

    Args:
        csv_file_path (str):        The file path to the csv file

    Returns:
        parameter_values (list):    A list of the parameter values over which the evaluation was done
        f1scores (list):            The corresponding f1scores
        precisions (list):          The corresponding precisions
        recalls (list):             The corresponding recalls
    '''
    if os.path.exists(csv_file_path):
        parameter_values = []
        f1scores         = []
        precisions       = []
        recalls          = []
        parameter_name   = None
        with open(csv_file_path) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            line_count = 0
            for row in csv_reader:
                if not row:
                    break
                if line_count == 0:
                    parameter_name = row[0]
                    if row[1] != 'f1score' or row[2] != 'precision' or row[3] != 'recall':
                        raise ValueError("Error: first line of csv needs to have the format <parameter_name>,f1score,precision,recall")
                else:
                    parameter_values.append(float(row[0]))
                    f1scores.append(100 * float(row[1]))
                    precisions.append(100 * float(row[2]))
                    recalls.append(100 * float(row[3]))
                line_count += 1

        return parameter_values, parameter_name, f1scores, precisions, recalls
    else:
        raise ValueError("Error: {0} doesnt exist")


def plot_values(x_values, x_label, f1scores, precisions, recalls):
    '''
    Plots a graph for the given x and y values
    '''

    if len(x_values) != len(f1scores) or len(x_values) != len(precisions) or len(x_values) != len(recalls):
        raise ValueError("Error: x_values and y_values arrays are not equal length")

    fig = plt.figure()
    ax  = plt.gca()

    exp = int(math.log10(max(x_values)))
    majors = []

    plt.plot(x_values, f1scores, label='F1 score', marker='x', color='red')
    plt.plot(x_values, precisions, label='Precision', marker='o', color='blue')
    plt.plot(x_values, recalls, label='Recall', marker='o', color='green')
    plt.xlabel('Approximation factor $\epsilon$')
    ax.set_xscale('log')
    plt.ylabel('Accuracy [%]')
    plt.legend()

    plt.show()

    #fig.savefig('test.png')

def main():
    csv_file_path, output_path = parser()

    parameter_values, parameter_name, f1scores, precisions, recalls = read_csv(csv_file_path)

    plot_values(parameter_values, parameter_name, f1scores, precisions, recalls)

if __name__ == '__main__':
    main()