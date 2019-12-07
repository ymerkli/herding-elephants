from __future__ import division

import json
import argparse
import os
import csv

class FlowEvaluator(object):
    '''
    Reads two JSONs with of flows (5-tuples)
    One JSON represent all flows in a PCAP file that are heavy hitters
    (according to a global threshold)
    The other JSON represents all found flows by the detection algorithm

    Args:
        csv_file_path (str):        The path to the csv file in which we want to write to
        eval_parameter_name (str): The name of the parameter over which we evaluate (e.g. epsilon)
    '''

    def __init__(self, csv_file_path, eval_parameter_name):
        self.csv_file_path        = csv_file_path
        self.eval_parameter_name = eval_parameter_name

    def read_flow_json(self, filepath, key):
        '''
        Reads a json containing a list of flows (5-tuples in string form)\
        The key to the flow array in the JSON is indicated by <key>

        Args:
            filepath (str): The filepath to the json file
            key (str):      The key in the json where the flow array is
        '''

        json_decoded = {}
        if os.path.exists(filepath):
            with open(filepath) as json_file:
                json_decoded = json.load(json_file)
                json_file.close()
        else:
            raise ValueError("Error: file {0} does not exist".format(filepath))

        if key not in json_decoded:
            raise ValueError("Error: key {0} not found in {1}".format(
                key, filepath
            ))

        return json_decoded[key]

    def performance(self, real_elephants, found_elephants):
        '''
        Calculates true positives, false positives and false negatives based on the provided
        flow sets.

        NOTE: flows are added as strings in the JSON files. This improves
        readability when using indentation.

        Args:
            real_elephants (list):  A list of flows (strings) with all heavy hitter flows
            found_elephants (list): A list of flows (strings) with the flows out algorithm classified
                                    as heavy hitters (elephants)

        Returns:
            tp (int):               True positives
            fp (int):               False positives
            fn (int):               False negatives
        '''

        tp = 0
        fp = 0
        fn = 0

        for flow in real_elephants:
            if flow in found_elephants:
                tp = tp+1
                found_elephants.remove(flow)
            else:
                fn = fn+1

        fp = len(found_elephants)

        print("performance: tp = {0}, fp = {1}, fn = {2}".format(tp, fp, fn))

        return tp, fp, fn

    def f1_score(self, tp, fp, fn):
        '''
        Calculates the F1 score
        '''

        f1_score = 0
        try:
            f1_score = (2 * tp) / (2 * tp + fp + fn)
        except ZeroDivisionError:
            print("Error: zero division in f1 score calculation")

        return f1_score 

    def precision(self, tp, fp, fn):
        '''
        Calculate the precision
        '''

        precision = 0
        try:
            precision = tp / (tp + fp) 
        except ZeroDivisionError:
            print("Error: zero division in precision calculation")

        return precision

    def recall(self, tp, fp, fn):
        '''
        Calculate the recall
        '''

        recall = 0
        try:
            recall = tp / (tp + fn)
        except ZeroDivisionError:
            print("Error: zero division in recall calculation")

        return recall

    def get_accuracy(self, real_elephants_fp, found_elephants_fp):
        '''
        Gets the F1score, precision, recall for two provided file paths to JSONs

        Args:
            real_elephants_fp (str):    File path to the JSON with the real
                                        elephant flows
            found_elephants_fp (str):   File path to the JSON with the found
                                        elephant flows

        Returns:
            f1_score (float):           The F1Score for the two flow sets
            precision (float):          The precision for the two flow sets  
            recall (float):             The recall for the two flow sets  
        '''

        real_elephants  = self.read_flow_json(real_elephants_fp, 'real_elephants')
        found_elephants = self.read_flow_json(found_elephants_fp, 'found_elephants')

        tp, fp, fn = self.performance(real_elephants, found_elephants)

        f1_score    = self.f1_score(tp, fp, fn)
        precision   = self.precision(tp, fp, fn)
        recall      = self.recall(tp, fp, fn)

        print("F1 = {0}, precision = {1}, recall = {2}".format(f1_score, precision, recall))

        return f1_score, precision, recall 

    def write_accuracies_to_csv(self, f1_score, precision, recall, eval_parameter_value):
        '''
        Writes the accuracy measures to the given csv file, on the line indicated
        by the eval_parameter_value

        Args:
            f1_score (float):   The F1 score
            precision (float):  The precision
            recall (float):     The recall
        '''

        if os.path.exists(self.csv_file_path):
            new_csv = []
            with open(self.csv_file_path) as csv_file:
                reader = csv.reader(csv_file)
                
                for row in reader:
                    '''
                    Append all rows to the new_csv list (which will later be written back)
                    for the row corresponding to the eval_parameter_value, we write the 
                    accuracy measures f1_score, precision, recall
                    '''
                    if row[0] == str(eval_parameter_value):
                        row = [row[0]]
                        row.append(f1_score)
                        row.append(precision)
                        row.append(recall)

                    new_csv.append(row)

                csv_file.close()

            with open(self.csv_file_path, 'w') as csv_file:
                writer = csv.writer(csv_file, lineterminator='\n')

                writer.writerows(new_csv)

                print("Wrote accuracies for {0} to {1}".format(eval_parameter_value, self.csv_file_path))
        else:
            raise ValueError("Error: csv file {0} does not exit".format(self.csv_file_path))
