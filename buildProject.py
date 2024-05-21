import os 
import time
import json
import signal
import logging
import argparse
from utils.key import *
from pathlib import Path
from utils.ghidra_helper import *
from utils.launcher import HeadlessLoggingPyhidraLauncher

log_time = time.strftime("%Y-%m-%d_%H:%M:%S")

def timeout_handler(signum, frame):
    raise TimeoutError("Timed out!")

def main(args):

    # pyhidra launcher 
    launcher = HeadlessLoggingPyhidraLauncher(verbose=True, log_path=f'./logs/Pyhidra_{args.project_name}_{log_time}.log')
    launcher.start()
    
    # create project
    from java.io import IOException
    from ghidra.base.project import GhidraProject
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.util.task import ConsoleTaskMonitor
    monitor = ConsoleTaskMonitor()

    # Create Project Dir and name 
    project_location = args.project_path
    project_location.mkdir(exist_ok=True, parents=True)
    project_name = args.project_name

    # create or open project 
    try:
        project = GhidraProject.openProject(project_location, project_name, True)
        logging.info(f'Opened project: {project.project.name}')
    except IOException:
        project = GhidraProject.createProject(project_location, project_name, False)
        logging.info(f'Created project: {project.project.name}')

    lang = get_language(lang_str())

    exist_bins_ = set()
    for file_ in project.getRootFolder().getFiles():
        exist_bins_.add(file_.getName())

    num = 0
    func_num = []
    start_time = time.time()
    analysis_time = time.time()
    signal.signal(signal.SIGALRM, timeout_handler)
    for root, dirs, files in os.walk(args.file_path):
        # filter out the json file 
        firmwares = [f for f in files if not f.endswith("json")]
        dir_ = Path(root)
        for file_ in firmwares: 
            firm_ = dir_ / file_
            noheader_ = firm_valid(dir_ / file_)
            if noheader_ is None:
                continue
            logging.info(f"Iter file {firm_} at {num}")
            monitor.setMessage(f"\033[31mIter file {firm_} at {num}\033[0m")
            # firmware has been analyzed 
            if noheader_ in exist_bins_:
                logging.info(f"Skip file {firm_} at {num} because ghidra project exist")
                continue 
            # timeout and try 
            logging.debug(f'import {noheader_.name} with base address {base_address(firm_)}')
            analysis_time = time.time()
            if noheader_.name.endswith('elf'):
                program = project.importProgram(noheader_)
            else:
                program = project.importProgram(noheader_, lang, get_compiler_spec(lang))
            signal.alarm(600)  
            try: 
                handler_num = 0
                flat_api = FlatProgramAPI(program)
                # edit when not elf 
                if not noheader_.name.endswith('elf'):
                    old_base = program.getImageBase()
                    image_base = base_address(firm_)
                    # 1. setImageBase (Address base, boolean commit)
                    program.setImageBase(old_base.getNewAddress(image_base), True)
                    # 2. create interrupt handlers 
                    handler_num = create_handlers(program, flat_api)
                flat_api.analyzeAll(program)
                analysis_time = int(time.time() - analysis_time)
                func_num.append([file_, handler_num, program.getFunctionManager().getFunctionCount(),os.path.getsize(noheader_), analysis_time])
                monitor.setMessage(f"\033[31mAdd {program.getFunctionManager().getFunctionCount()} functions\033[0m")
                logging.info(f"Add {program.getFunctionManager().getFunctionCount()} functions")
                num += 1
            except TimeoutError:
                logging.info(f"Analyze {file_} timeout!!")
                func_num.append([file_,-1,-1,os.path.getsize(noheader_),-1])
            finally:
                signal.alarm(0)
            project.saveAs(program, "/", program.getName(), True)
            project.close(program)
            break 
    # write csv 
    with open(f'./res/func_num_{project_name}.csv', 'w') as file:
        file.write('Program, Handlers, Functions, Size, AnalysisTime\n')
        for i in func_num:
            line = ""
            for j in i:
                line += str(j) + ", "
            line = line[:-2] + '\n'
            file.write(line)
    # end
    logging.info("Finish: total annalysis time {time.time() - start_time}")
    project.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Create Fid database from ghdira project")
    parser.add_argument("project_path",type=Path,default=Path('./ghidra_projects'))
    parser.add_argument("project_name",default="arm_firms")
    parser.add_argument("file_path",default="./firmwares/",help="Path of firmware files")
    parser.add_argument("-s", "--script",type=Path,default=Path("./utils/valid.py"), help="Script of firmware valid functions")
    args = parser.parse_args()
    # log
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
    logging.basicConfig(filename=f'./logs/buildProject_{args.project_name}_{log_time}.log', level=logging.DEBUG, format=LOG_FORMAT, datefmt=DATE_FORMAT)
    try:
        if not args.project_path.exists():
            logging.error("Invalid project path")
        elif not args.script.exists():
            logging.error("Invalid valid script")
        else:
            # exec valid script
            with open(args.script, 'r') as file:
                exec(file.read())
            main(args)
    except KeyboardInterrupt:
        logging.error("Exit with keyboard")
        project.close() 
