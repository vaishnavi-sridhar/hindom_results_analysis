import re
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--threshold', type=int, default=0, help="Need to input the threshold")
    FLAGS = parser.parse_args()
    filename = "convergence_log_700k.txt"
    F_start = 0
    label_start = 0
    F_end = 0
    label_end = 0
    count = 0
    count_mal = 0
    count_ben = 0
    count_accurate = 0
    list_mal = []
    list_ben = []
    f = open("results_analysis.csv", "w")
    with open(filename, "r") as infile:
        for line in infile:
            for i in re.finditer('\[', line):
                count = count + 1
                if count % 2 == 0: # when it is even its the second [ so start of f
                    F_start = i.end()
                    #print("This is F start", F_start)#should be 8
                else:#odd
                    label_start = i.end()
                    #print("This is Labels start", label_start)#should be 1
            for m in re.finditer('\]', line):
                count = count + 1
                if count % 2 == 0: # when it is even its the second [ so start of f
                    F_end = m.start()
                    #print("This is F end", F_end)#should be 29
                else:#odd
                    label_end = m.start()
                    #print("This is Labels end", label_end)#should be 6
            label = line[label_start:label_end]
            F = line[F_start:F_end]
            domain = line[F_end+1:len(line)-1]
            F_values = F.split()
            delta_val = float(F_values[1]) - float(F_values[0])
            if label == "0. 0." or label == "0. 1.":
                tag1 = "benign"
            else:
                tag1 = "malicious"
            if delta_val < FLAGS.threshold: #we can change the threshold here so maybe it isn't 0
                tag = "malicious"
                count_mal = count_mal + 1
                list_mal.append(domain)
                if label == "1. 0.":
                    count_accurate = count_accurate + 1
                    tag1 = "malicious"
            else:
                tag = "benign"
                count_ben = count_ben + 1
                list_ben.append(domain)
                if label == "0. 0." or label == "0. 1.":
                    count_accurate = count_accurate + 1
            f.write(str(domain) +  "," + str(tag) +  "," + str(delta_val) + "," + str(tag1) + "\n")
    print("Count of malicious domains: ", count_mal)
    print("Count of benign domains: ", count_ben)
    print("Count of tag matching label: ", count_accurate)
    print("Accuracy: ", count_accurate/(count_ben + count_mal))
    f.close()
if __name__ == '__main__':
  main()
