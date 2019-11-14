import random

##### Given #####
# (T) glob_thresh -> Global threshold
# (C) comm_budget -> Communication budget per switch
# (S) switch_mem -> Memory budget per switch (# counters)
# (k) ingress_switches -> Total number of ingress switches
# (l) observers -> Number of switches which observe a flow
# (D) train_data -> Training Data

##### Determine #####
# epsilon -> Approximation Factor
# (tau) mule_tau -> Local (Mule) threshold
# (M) moles -> Set of moles observed at switch
# (U) mules -> Set of mules at a switch
# (r) report_prob -> Reporting probability to coordinator
# (s) sampl_prob -> Sampling probability at a switch
# (R) report_thresh -> coordinator identifies as mule as a network-wide
#                      heavy hitter if it receives R reports

# determine the highest possible sampling prob-ability,
# given the memory constraint
def GetSampling(switch_mem, train_data, mole_tau):
    sampl_prob = 1/(mole_tau)
    moles = CalculateMoles(train_data, sampl_prob)
    while len(moles) < switch_mem:
        mole_tau = mole_tau - 1
        moles = CalculateMoles(train_data, sampl_prob)
    return mole_tau
# configures reporting parameters based on the gives contraints
def DeriveReporting(comm_budget, epsilon, observers, sampl_prob):
    mule_tau = epsilon * glob_thresh / observers
    moles = CalculateMoles(train_data, sampl_prob)
    mules = CalculateMules(moles, mule_tau)
    report_prob = comm_budget * mule_tau / (glob_thresh * len(mules))
    report_thresh = observers * report_prob / glob_thresh
    return report_thresh, mules, report_prob, mule_tau

# determine the accuracy of the System
def TuneAccuracy(glob_thresh, switch_mem, comm_budget, train_data, observers):
    accuracy_max = 0
    mole_tau = GetSampling(switch_mem, train_data, glob_thresh)
    sampl_prob = 1 / mole_tau
    eps_min = observers / glob_thresh # Theorem 1?
    eps_max = 1 # Theorem 2?
    sigma = observers / glob_thresh # Theorem 4
    while epsilon in range(eps_max, eps_min):
        report = DeriveReporting(comm_budget, epsilon, observers, sampl_prob)
        accuracy = GetAccuracy(train_data, report[0], glob_thresh, report[1],
                               report[2], sampl_prob, report[3])
        if accuracy >= accuracy_max:
            eps_max = epsilon
            epsilon = epsilon - sigma
            accuracy_max = accuracy
        else:
            break
# determine the accuracy of the System using this parameter configuration
def GetAccuracy(train_data, report_thresh, glob_thresh, mules, report_prob, sampl_prob, mule_tau):
    pass
    # return accuracy

# iterate through Training Data and add a sample with probability sampl_prob to moles
def CalculateMoles(train_data, sampl_prob):
    moles = {}
    for i in train_data.key:
        if random.randint(0, 1) <= sampl_prob:
            moles[i] = train_data[i]
    return moles

# iterate through moles and add moles with at least mule_tau traffic packets
def CalculateMules(moles, mule_tau):
    mules = {}
    for i in moles.key:
        if moles[i] >= mule_tau:
            mules[i] = moles[i]
    return mules

# if tuningparameters.py gets run as script
if __name__ == "__main__":
    print("tuningparameters is run as a script")
