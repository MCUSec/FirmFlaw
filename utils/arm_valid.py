from pathlib import Path 
import json
'''
the function used to filter the valid firmware and 
'''

arm_base_address = {}

def lang_str() -> str:
    return "ARM:LE:32:Cortex"

def remove_header(firmware: Path, info : dict) -> Path:
    if info.get('file offset') is None:
        return None
    file_offset = info['file offset']
    with open(firmware, 'rb') as input_file:
        input_file.seek(file_offset)
        remaining_data = input_file.read()
    noheader_ = firmware.with_name(firmware.name + 'noheader')
    with open(noheader_, 'wb') as output_file:
        output_file.write(remaining_data)
    return noheader_

def base_address(firmware: Path):
    return arm_base_address.get(firmware.name)

def firm_valid(firmware: Path) -> Path:
    global arm_base_address
    if arm_base_address.get(firmware.name) is not None:
        logging.info(f'Skip: duplicated {firmware} file, skip')
        return None 
    # name valid
    pass_extentions = ['hex', 'srec', 'ext4', 'wav']
    for ext_ in pass_extentions:
        if ext_ in firmware.name:
            logging.error('Skip: unsupported file extension {ext_} for {firmware}, skip')
            return None
    # hard code
    if firmware.name.startswith('simulator_video'):
        return None 
    # hard code
    if firmware.name.startswith("CoreNatureDictionary.ngram.mini.txt.table.bin"):
        return None
    # name valid end 

    info_file = firmware.with_name(firmware.name + '_firminfo.json')
    if not info_file.exists():
        logging.error(f'Skip: no info file for {firmware}, skip')
        return None
    with open(info_file, 'r') as file:
        info_ = json.load(file)
    if info_.get('base address') is None or \
    info_.get('architecture') is None or \
    info_.get('file offset')  is None or \
    len(info_['base address']) == 0 or \
    info_['architecture'] != "arm":
        logging.error(f'Skip: not valid info for {firmware}, skip')
        return None
    arm_base_address[firmware.name] = info_['base address']
    return remove_header(firmware, info_)

