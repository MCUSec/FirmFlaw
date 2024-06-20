import logging 
import argparse 
import os
from pathlib import Path
import math

def md_table(row, col, data):
    
    if len(data) != len(row) or len(data[0]) != len(col):
        print(f'Error: data:{data} not match row:{row} col:{col}')
    str_ = "| "
    split_ = "|-"
    for i in col:
        str_ += "|" + i
        split_ += "|-"
    str_ += "|\n" + split_ + "|\n"
    for (idx,item) in enumerate(row):
        str_ += "|" + item
        for j in data[idx]:
            str_ += f"| {j:.2f}"
        str_ += "|\n"
    return str_

def best_match(prefix):
    '''
    find the best match result using prefix string
    based on file size 
    '''
    max_size = 0
    match_ = None 
    for i in os.listdir('./res/'):
        if not i.startswith(prefix):
            continue
        path_ = Path(f'./res/{i}')
        size_ = os.path.getsize(path_)
        if size_ > max_size:
            max_size = size_
            match_ = path_
    if match_ is None:
        print(f"Error: no match file with prefix {prefix}")
        return None
    return match_

def std_dev(data):
    n = len(data)
    mean = sum(data) / n
    variance = sum((x - mean) ** 2 for x in data) / n
    return math.sqrt(variance)

def median(arr):
    sorted_arr = sorted(arr)
    n = len(sorted_arr)
    
    if n % 2 == 0:
        # even
        mid1 = sorted_arr[n//2 - 1]
        mid2 = sorted_arr[n//2]
        return (mid1 + mid2) / 2
    else:
        # odd
        return sorted_arr[n//2]

# Complexity: function and size 
def complexity_arm():
    # ARM
    with open('./res/func_num_arm_bins.csv') as file:
        lines = file.readlines()
    
    arm_funcs = []
    arm_size = []
    for line in lines[1:]:
        s_ = line.split(',')
        funcs_ = int(s_[2])
        size_ = int(s_[3])
        if funcs_ == 0:
            continue
        arm_funcs.append(funcs_)
        # KB
        arm_size.append(size_/1024)
    table6_arm = md_table(['Func.#','Size(KB)'], ['Mean','Median','SD'], [[sum(arm_funcs)/len(arm_funcs),median(arm_funcs),std_dev(arm_funcs)], \
                                                                          [sum(arm_size)/len(arm_size),median(arm_size),std_dev(arm_size)]])
    # Distribution
    t1 = 100
    t2 = 1500
    bars = [0,0,0]
    for i in arm_funcs:
        if 0 < i <= t1:
            bars[0] += 1
        elif t1 < i <= t2:
            bars[1] += 1
        elif t2 < i:
            bars[2] += 1
    figure3_arm = md_table(['ARM'],['1-100','100-1500','>1500'],[bars])       

    t1 = 50
    t2 = 100
    bars = [0,0,0]
    for i in arm_size:
        if 0 <= i <= t1:
            bars[0] += 1
        elif t1 < i <= t2:
            bars[1] += 1
        elif t2 < i:
            bars[2] += 1
    figure4_arm = md_table(['ARM'],['<50KB','50KB-100KB','>100KB'],[bars]) 
    
    return (table6_arm, figure3_arm, figure4_arm)

def complexity_xtensa():
    # Xtensa
    with open('./res/func_num_xtensa_bins.csv') as file:
        lines = file.readlines()
    
    xtensa_funcs = []
    xtensa_size = []
    for line in lines[1:]:
        s_ = line.split(',')
        funcs_ = int(s_[2])
        size_ = int(s_[3])
        if funcs_ == 0:
            continue
        xtensa_funcs.append(funcs_)
        # KB
        xtensa_size.append(size_/1024)
    table6_xtensa = md_table(['Func.#','Size(KB)'], ['Mean','Median','SD'], [[sum(xtensa_funcs)/len(xtensa_funcs),median(xtensa_funcs),std_dev(xtensa_funcs)], \
                                                                              [sum(xtensa_size)/len(xtensa_size),median(xtensa_size),std_dev(xtensa_size)]])

    # Distribution
    t1 = 100
    t2 = 1500
    bars = [0,0,0]
    for i in xtensa_funcs:
        if 0 < i <= t1:
            bars[0] += 1
        elif t1 < i <= t2:
            bars[1] += 1
        elif t2 < i:
            bars[2] += 1
    figure3_xtensa = md_table(['Xtensa'],['1-100','100-1500','>1500'],[bars])       

    t1 = 50
    t2 = 100
    bars = [0,0,0]
    for i in xtensa_size:
        if 0 <= i <= t1:
            bars[0] += 1
        elif t1 < i <= t2:
            bars[1] += 1
        elif t2 < i:
            bars[2] += 1
    figure4_xtensa = md_table(['Xtensa'],['<50KB','50KB-100KB','>100KB'],[bars])
    
    return (table6_xtensa, figure3_xtensa, figure4_xtensa)

def main(args):
    md_ = "# Results\n\n## Complexity Anlaysis\n\n"
    (table6_arm, figure3_arm, figure4_arm) = complexity_arm()
    md_ += f"### ARM\n {table6_arm}\n\nDistribution of function number\n{figure3_arm}\n\nDistribution of firmware size\n{figure4_arm}\n\n" 
    (table6_xtensa, figure3_xtensa, figure4_xtensa) = complexity_xtensa()
    md_ += f"### Xtensa\n {table6_xtensa}\n\nDistribution of function number\n{figure3_xtensa}\n\nDistribution of firmware size\n{figure4_xtensa}\n\n"
    md_ += '## Library Adoption Analysis'
    
    with open('./res/results.md','w') as file:
        file.write(md_)

# ESP Xtensa Lib Adoptation
def read_tags(tags):
    '''
    read function name from tags
    tags: generated by ctag 
    '''
    funcs_ = set()
    with open(tags, 'r') as file:
        tags = file.readlines()
    for line in tags:
        names = line.split('\t')
        if names[-2] == 'f':
            funcs_.add(names[0])
    return funcs_

def read_symbol(sym_file):
    '''
    read function name from symbol file 
    symbol_file: generated from library using objdump 
    '''
    funcs_ = set()
    with open(sym_file, 'r') as file:
        lines = file.readlines()
    for line in lines:
        if ' F ' in line: # is functions
            funcs_.add(line.split()[-1])
    return funcs_

# The ESP LIB Match
esp_funcdb = {
'esp-phy': read_symbol('./tags/esp-phy-lib.symbol'),
'esp-lwip': read_tags('./tags/esp-lwip.tags'),
'esp-mqtt': read_tags('./tags/esp-mqtt.tags'),
'esp-wifi': read_symbol('./tags/esp32-wifi-lib.symbol'),
'esp-openthread': read_tags('./tags/esp-openthread.tags') | read_symbol('./tags/esp-thread-lib.symbol'),
'esp-mbedtls': read_tags('./tags/mbetls.tags'),
'esp-bt': read_symbol('./tags/esp32-bt-lib.symbol'),
'esp-hal': read_tags('./tags/esp-idf-hal.tags'),
'esp-freertos': read_tags('./tags/freertos-tags'),
}


def count(type, program, lib_match):
    '''
    count the number of match type by program and store it to lib_match
    '''
    if lib_match.get(type) is None:
        lib_match[type] = {}
    if lib_match[type].get(program) is None:
        lib_match[type][program] = 1
    else:
        lib_match[type][program] += 1

def collect(type, program, match, lib_match):
    '''
    seperate the match by type 
    '''
    if lib_match.get(type) is None:
        lib_match[type] = {}
    if lib_match[type].get(program) is None:
        lib_match[type][program] = [match]
    else:
        lib_match[type][program].append(match)

def match_program(match_res, funcdb_map):
    '''
    calculate the match from match result json file 
    '''
    import json
    lib_match = {} # match number 
    lib_match_full = {}
    program_match = set()
    with open(match_res, 'r') as f:
        data = json.load(f)
    for (program, v) in data.items():
        program_match = set()
        for (func, match) in v.items():
            for (t, db_) in funcdb_map.items():
                # bt
                # functionID result 
                if isinstance(match, list):
                    if match[0][0] in db_:
                        # test
                        if match[0][0] in progam_match:
                            print(f'find {match[0][0]} in {program}')
                        program_match.add(match[0][0])
                        # test end
                        count(t, program, lib_match)
                        collect(t, program, {func: match}, lib_match_full)
                # SimMatch result 
                elif match['name'] in db_:
                    count(t, program, lib_match)
                    collect(t, program, {func: match}, lib_match_full)
    return (lib_match, lib_match_full)

def main(args):
    


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Generate the Result from file")
    parser.add_argument("match_result",type=Path,helper="JSON based result from functionID or SimMatch")
    parser.add_argument("threshold",default=2,helper="the threshold of match times to generate library adoption")
    args = parser.parse_args()
    # log
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
    logging.basicConfig(filename=f'./logs/ResGen_{log_time}.log', level=logging.DEBUG, format=LOG_FORMAT, datefmt=DATE_FORMAT)
    try:
        main(args)
    except KeyboardInterrupt:
        logging.error("Exit with keyboard")
        project.close() 
