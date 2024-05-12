# define the similar percentage functions 
from difflib import SequenceMatcher
import sqlite3
from functools import reduce
from operator import mul
# the configurations 
TOLERANT_ = 0.1 # tolerant level: 90%
ACCEPT_ = 0.95 # accept level: >95%

# Task 5.1: Define some functions to calculate the similar percentage of two functions  
# the percentage of different attributes 
def diff_percentage(base: tuple, param: tuple) -> float:
    '''
    compute the percentage of different tuple
    base: been compared
    param: want to compare
    '''
    if len(base) != len(param):
        print("ERROR: different diff length")
        return 0
    return sum(abs(i-j)/i for (i,j) in zip(base,param)) / len(base)
    
# Task 5.2: Find [several] most similar functions with the input func
def compare_func(cursor: sqlite3.Cursor, func: 'ghidra.program.model.listing.Function') -> list:
    '''
    find the most match function and several candidate functions
    by compare keys we defined and the mnemonic strings  
    '''
    inst_ = get_inst_key(func_)
    graph = get_struct_graph_key(func_)
    # make sure the inst_[0] means the numAddress 
    hash_ = reduce(mul,(n for n in graph),1) * inst_[0]
    cursor.execute(f'SELECT * FROM {FUNC_TABLE_NAME} WHERE hash BETWEEN ? AND ? ORDER BY ABS(hash-?)', (round(hash_ * (1-TOLERANT_)), round(hash_ * (1+TOLERANT_)), hash_))
    results = cursor.fetchall()
    
    # filter the remain results
    matches = []
    max_ = [(1,),0]
    for result_ in results:
        # compare every attributes
        same_ = 1 - diff_percentage(graph, result_[5:9])
        if same_ < ACCEPT_:
            continue
        match = SequenceMatcher(lambda x: x == ',', result_[4], inst_[1], autojunk=False)
        if match.quick_ratio() < ACCEPT_ or (ratio_ := match.ratio()) < ACCEPT_:
            continue
        if max_[1] < (same_ + ratio_):
            max_[1] = (same_ + ratio_) / 2
            max_[0] = result_
        matches.append([result_,(same_+ratio_)/2])
    return (max_, matches)


# import for func_key_idx
def compare_func_db(cursor: sqlite3.Cursor, func_row: tuple) -> list:
    '''
    find the most match function and several candidate functions
    by compare keys we defined and the mnemonic strings
    '''
    from .db import FUNC_KEYS, func_key_idx, FUNC_TABLE_NAME
    hash_ = func_row[func_key_idx('hash')]
    cursor.execute(f'SELECT * FROM {FUNC_TABLE_NAME} WHERE hash BETWEEN ? AND ? ORDER BY ABS(hash-?)', (round(hash_ * (1-TOLERANT_)), round(hash_ * (1+TOLERANT_)), hash_))
    results = cursor.fetchall()
    # filter the remain results
    matches = []
    max_ = [(1,),0]
    for result_ in results:
        # del the id
        result_ = result_[1:]
        # compare every attributes
        same_ = 1 - diff_percentage(func_row[func_key_idx('block_num'):func_key_idx('jump_num')+1], result_[func_key_idx('block_num'):func_key_idx('jump_num')+1])
        if same_ < ACCEPT_:
            continue
        match = SequenceMatcher(lambda x: x == ',', result_[func_key_idx('mnemonics')], func_row[func_key_idx('mnemonics')], autojunk=False)
        if match.quick_ratio() < ACCEPT_ or (ratio_ := match.ratio()) < ACCEPT_:
            continue
        if max_[1] < (same_ + ratio_):
            max_[1] = (same_ + ratio_) / 2
            max_[0] = result_
        matches.append([result_,(same_+ratio_)/2])
    return (max_, matches)

import time
# import for func_key_idx
def compare_func_db_time(cursor: sqlite3.Cursor, func_row: tuple) -> list:
    '''
    find the most match function and several candidate functions
    by compare keys we defined and the mnemonic strings  
    '''
    from .db import FUNC_KEYS, func_key_idx, FUNC_TABLE_NAME
    hash_ = func_row[func_key_idx('hash')]
    time_1 = time.time_ns()
    cursor.execute(f'SELECT * FROM {FUNC_TABLE_NAME} WHERE hash BETWEEN ? AND ? ORDER BY ABS(hash-?)', (round(hash_ * (1-TOLERANT_)), round(hash_ * (1+TOLERANT_)), hash_))
    results = cursor.fetchall()
    time_2 = time.time_ns()
    first_len = len(results)
    # filter the remain results 
    matches = []
    max_ = [(1,),0]
    for result_ in results:
        # del the id 
        result_ = result_[1:]
        # compare the 
        same_ = 1 - diff_percentage(func_row[func_key_idx('block_num'):func_key_idx('jump_num')+1], result_[func_key_idx('block_num'):func_key_idx('jump_num')+1])
        if same_ < ACCEPT_:
            continue
        match = SequenceMatcher(lambda x: x == ',', result_[func_key_idx('mnemonics')], func_row[func_key_idx('mnemonics')], autojunk=False)
        if match.quick_ratio() < ACCEPT_ or (ratio_ := match.ratio()) < ACCEPT_:
            continue
        if max_[1] < (same_ + ratio_):
            max_[1] = (same_ + ratio_) / 2
            max_[0] = result_
        matches.append([result_,(same_+ratio_)/2])
    time_3 = time.time_ns()
    return (max_, matches, time_2 - time_1, time_3 - time_2, first_len, len(matches)) 
