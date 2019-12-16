import matplotlib
import matplotlib.pyplot as plt
import numpy as np


labels = ['0,1', '0,15', '0,2']
rla_comm = [10200, 10100, 9700]
ps_comm = [10000, 15000, 20000]
herd_comm = [15500, 14800, 12000]
strawman_comm = [23100,23100,23100]

labels_mem = ['0,1', '0,15', '0,2']
rla_mem = [23100, 23100, 23100]
herd_mem = [4600, 6700, 8300]
strawman_mem = [23100,23100,23100]

x = np.arange(len(labels))  # the label locations
width = 0.15  # the width of the bars

fig_1, ax_1 = plt.subplots()
fig_2, ax_2 = plt.subplots()

rects1 = ax_1.bar(x - 1.5*width, rla_comm, width, label='Probabilistic reporting', color='b')
rects2 = ax_1.bar(x + 0.5*width, ps_comm, width, label='Probabilistic sampling (s = epsilon)', color='g')
rects3 = ax_1.bar(x - 0.5*width, herd_comm, width, label='Herd', color='r')
rects4 = ax_1.bar(x + 1.5*width, strawman_comm, width, label='Strawman', color='c')
rects_a1 = [rects1, rects3, rects2, rects4]

rects5 = ax_2.bar(x , rla_mem, width, label='Probabilistic reporting', color='b')
rects7 = ax_2.bar(x - width, herd_mem, width, label='Herd', color='r')
rects8 = ax_2.bar(x + width, strawman_mem, width, label='Strawman', color='c')
rects_a2 = [rects5, rects7, rects8]

# Add some text for labels, title and custom x-axis tick labels, etc.
ax_1.set_ylabel('Messages', fontsize = 20)
ax_1.set_title('Communication usage', fontsize = 20)
ax_1.set_xlabel('Epsilon',  fontsize = 20)
ax_1.set_xticks(x)
ax_1.set_xticklabels(labels)
ax_1.legend(loc=4, prop={'size': 18})


# Add some text for labels, title and custom x-axis tick labels, etc.
ax_2.set_ylabel('States',  fontsize = 20)
ax_2.set_title('Memory usage', fontsize = 20)
ax_2.set_xlabel('Epsilon',  fontsize = 20)
ax_2.set_xticks(x)
ax_2.set_xticklabels(labels)
ax_2.legend(loc=4,prop={'size': 18})


def autolabel_a1(rects):
    """Attach a text label above each bar in *rects*, displaying its height."""
    for rect in rects:
        height = rect.get_height()
        ax_1.annotate('{}'.format(height),
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')

def autolabel_a2(rects):
    """Attach a text label above each bar in *rects*, displaying its height."""
    for rect in rects:
        height = rect.get_height()
        ax_2.annotate('{}'.format(height),
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')

for i in range (0,4):
    autolabel_a1(rects_a1[i])
for i in range (0,3):
    autolabel_a2(rects_a2[i])

fig_1.tight_layout()
fig_2.tight_layout()

plt.show()
