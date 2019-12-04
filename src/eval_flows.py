import json
import argparse

class FlowEvaluator(object):
    '''
    Reads two JSONs with of flows (5-tuples)
    One JSON represent all flows in a PCAP file that are heavy hitters
    (according to a global threshold)
    The other JSON represents all found flows by the detection algorithm
    '''

    def __init__(self):

    def read_flow_json(self, filepath):
        json_decoded = {}
        if os.path.exists(filepath):
            with open(filepath) as json_file:
                json_decoded = json.load(json_file)
                json_file.close()
        else:
            raise ValueError("Error: file {0} does not exist":format(filepath))

        return json_decoded['flow'] 


        pcap_file_name = re.match(r"^(.+/)*(.+)\.(.+)", file).group(2)

    def performance(self, found_elephants, real_elephants):
        '''
        Calculates true positives, false positives and false negatives based on the provided
        flow sets.

        NOTE: flows are added as strings in the JSON files. This improves
        readability when using indentation.
    
        Args:
            found_elephants (list): A list of flows (strings) with the flows out algorithm classified
                                    as heavy hitters (elephants)
            real_elephants (list):  A list of flows (strings) with all heavy hitter flows
    
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
                real_elephants.remove(flow)
                found_elephants.remove(flow)
            else:
                fn = fn+1
                real_elephants.remove(flow)

        fp = len(found_elephants)

        print("performance: tp = {0}, fp = {1}, fn = {2}".format(tp, fp, fn))
    
        return tp, fp, fn

    def f1_score(self, tp, fp, fn):
        '''
        Calculates the F1 score
        '''

        return (2 * tp) / (2 * tp + fp + fn)

    def get_accuracy(self, real_elephants_fp, found_elephants_fp):
        '''
        Gets the accuracy (F1 score) for two provided file paths to JSONs

        Args:
            real_elephants_fp (str):    File path to the JSON with the real
                                        elephant flows
            found_elephants_fp (str):   File path to the JSON with the found
                                        elephant flows

        Returns:
            f1_score (float):           The F1Score for the two flow sets
        '''

        real_elephants  = self.read_flow_json(real_elephants_fp)
        found_elephants = self.read_flow_json(found_elephants_fp)

        tp, fp, fn = self.performance(real_elephants, found_elephants)

        return self.f1_score(tp, fp, fn)

def parser():
    parser = argparse.ArgumentParser(description= 'parse the keyword arguments')

    parser.add_argument(
        '--r',
        type=str,
        required=True,
        help='The filepath to the real elephants JSON'
    )

    parser.add_argument(
        '--f',
        type=str,
        required=True,
        help='The filepath to the found elephants JSON'
    )

    args = parser.parse_args()

    return args.r, args.f

def main():
    real_elephants, found_elephants = parser()

    evaluator = FlowEvaluator()

    f1_score = evaluator.get_accuracy(real_elephants, found_elephants)

