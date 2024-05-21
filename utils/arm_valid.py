from pathlib import Path 
import json
'''
the function used to filter the valid firmware and 
'''

arm_base_address = {}

def lang_str() -> str:
    return "ARM:LE:32:Cortex"

def remove_header(firmware: Path, info : dict) -> Path:
    file_offset = 0
    if info.get('file offset') is not None:
        file_offset = info['file offset']
    with open(firmware, 'rb') as input_file:
        input_file.seek(file_offset)
        remaining_data = input_file.read()
    noheader_ = firmware.with_name(firmware.name + 'noheader')
    with open(noheader_, 'wb') as output_file:
        output_file.write(remaining_data)
    return noheader_

def base_address(firmware: Path):
    if (ba_ := arm_base_address.get(firmware.name)) is None:
        logging.error(f"Ask for not check valid firmware {firmware.name}")
        return 0
    return ba_

def firm_valid(firmware: Path) -> Path:
    global arm_base_address
    if arm_base_address.get(firmware.name) is not None:
        logging.info(f'Skip: duplicated {firmware} file, skip')
        return None 
    logging.debug(f"Check {firmware.name} arm_valid start")
    # name valid
    skip_extentions = ['hex', 'srec', 'ext4', 'wav']
    for ext_ in skip_extentions:
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
    ## Start info check 
    with open(info_file, 'r') as file:
        info_ = json.load(file)
    # architecture
    if info_.get('architecture') is None or info_['architecture'] != 'arm':
        logging.debug(f'Skip: not arm firmware-{firmware}')
        return None
    # base address
    base_address = 0
    # TODO: 0x-1 is hahaha
    if (ba_ := info_.get('base address')) is not None and ba_ != '0x-1': 
        base_address = int(ba_[2:], base=16)
    arm_base_address[firmware.name] = base_address
    return remove_header(firmware, info_)

