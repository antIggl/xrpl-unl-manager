#!/usr/bin/env python3


import sys
import utils
import scenario_utils as scutils
import encodeUNL
import os
import sched
import json

import time
import daemon
import signal
import lockfile

CONFIG_FILE_USE=r"""
Configuration file in in INI format and should include at least.
The command line argument values overwrites the defaults and the configuration file ones.
Example:
    [daemon]
    working_directory = /var/xrpl-unl-manager/
    # working_directory = /opt/xrpl-unl-manager
    status_file = ${working_directory}/unl-manager.running
    pid_file = ${working_directory}/unl-manager.pid
    log_file = /var/log/xrpl-unl-manager/unl-manager-daemon.log
    log_level = DEBUG
    scenario_file = /etc/xrpl-unl-manager/unl-scenario.json
    publish_path = /var/www/xrpl-unl-manager/unls/
    keys_path = ${working_directory}/validators-config/
    keys_file = /etc/xrpl-unl-manager/unl-generator-token.txt

    [standalone]
    working_directory = ./
    status_file = ${working_directory}/unl-manager.running
    pid_file = ${working_directory}/unl-manager.pid
    log_file = ${working_directory}/unl-manager-daemon.log
    log_level = DEBUG
    scenario_file = ${working_directory}/unl-scenario.json
    publish_path = ${working_directory}/publish/unls/
    keys_path = ${working_directory}/validators-config/
    keys_file = ${working_directory}/unl-generator-token.txt

"""

DEFAULT_PUBLISHED_UNL_FILENAME="index.html"
UNL_FILENAME_PATTERN="{validator_name}_t{simtime}.json"



def generateValidatorUNLAtTime(mscenario,unlPubToken,keys_path,validator,timestamp):
    """Generates Validator UNL at specified Time

    Args:
        mscenario (scenario_utils.UNLScenario): The scenario used to extract the UNL
        unlPubToken ([type]): [description]
        keys_path ([type]): [description]
        validator ([type]): [description]
        timestamp ([type]): [description]
    """
    vUNL= mscenario.getValidatorUNLAtTime(validator,timestamp)
    munl= utils.createUNL(vUNL,unlPubToken,1,keys_path)

    return munl


def getCmdArgumentsOptions(parser):
    """Returns all the destination attributes of all options of the argument parser

    Args:
        parser (argparse.ArgumentParser): The argument parser used for input

    Returns:
        Set : a Python set with all the destination attribute names for all the options
    """
    ret=set()
    for it in parser.__dict__['_option_string_actions'].values():
        ret.add(it.dest)
    return ret    

def updateSymlink(link_name, target):
    """Updates the symbolic link

    Args:
        link_name (str - pathname): name of the link
        target (str - pathname):name of the actual file

    Returns:
        1 : on failure
        0 : on success
    """
    if not os.path.exists(target):
        print("ERROR: updateSymlink() : target= %s does not exist."%target)
        return 1
    relpath=os.path.relpath(target,os.path.dirname(link_name))
    
    if os.path.islink(link_name):
        os.remove(link_name)

    # create symlink to target
    # os.symlink(src=target,dst=link_name)
    os.symlink(src=relpath,dst=link_name)
    return 0

def generateUNLsAtTime(mscenario,unlPubToken,pub_path,keys_path,timestamp):
    """Generated the UNLs for all the validators of the scenario at the given timestamp

    Args:
        mscenario ([type]): scenario object
        unlPubToken ([type]): UNL publisher keys-pair token
        pub_path ([type]): Publish path
        keys_path ([type]): Validators key path
        timestamp ([type]): Timestamp to read the UNL from the scenario file.
    """
    for v in mscenario.validators:
        fpath=pub_path+'/unls/'+v+'/'+ UNL_FILENAME_PATTERN.format(validator_name=v,simtime=timestamp)
        print("\t Generating UNL for %s in file %s"%(v,fpath))
        munl=generateValidatorUNLAtTime(mscenario,unlPubToken,keys_path,v,timestamp)
        with open(fpath,'w') as f:
            json.dump(munl,f)
        updateSymlink(os.path.dirname(fpath)+'/'+DEFAULT_PUBLISHED_UNL_FILENAME,fpath)            
        #updateSymlink(os.path.dirname(fpath)+'/'+DEFAULT_PUBLISHED_UNL_FILENAME,'./'+os.path.basename(fpath))            
        print ("\t \t Done!")
        # mscV=scutils.ScenarioVisualizer(msc)

        # mdotg=mscV.getUNLGraphAtTime(0)
        # mdotg.render('./testout.gv',view=True)
    

if __name__=='__main__':
    import argparse
    import configparser

    argparser=argparse.ArgumentParser(description="Manages the UNL files for a Ripple Testnet.")
    cmdgroup=argparser.add_mutually_exclusive_group(required=False)
    cmdgroup.add_argument("--start", help="Starts running the scenario file.", action="store_true")
    cmdgroup.add_argument("--stop", help="Stops the running process on the same publish path", action="store_true")
    cmdgroup.add_argument("--status", help="Prints the current state of the running process.", action="store_true")
    cmdgroup.add_argument("--reload", help="Reloads configuration from files", action="store_true")
    cmdgroup.add_argument("--restart", help="Restarts Daemon process.", action="store_true")

    # cmdgroup.set_defaults()
    argparser.add_argument("-d","--daemon", help="Runs as a daemon.", default=False, action="store_true")

    argparser.add_argument("-sf","--status-file",type=str, 
                                help="Defines the status file.") #default='./unl-manager/unl-manager.running',
    argparser.add_argument("-pid","--pid-file",type=str, 
                                help="Defines the pid locking file.") #default='./unl-manager/unl-manager.pid',
    argparser.add_argument("-workdir","--working-directory",type=str,
                                help="Defines the working directory. ")# default='./',
    argparser.add_argument("-log","--log-file",type=str, 
                                help="Defines the working directory. ") #default='./',

    argparser.add_argument("-conf","--config-file",type=str,default=os.environ.get('UNL_MANAGER_CONFIGFILE') if os.environ.get('UNL_MANAGER_CONFIGFILE') else './unl-manager.conf',
                                help="""Defines the configuration file.""")# + CONFIG_FILE_USE)

    argparser.add_argument("-sc","--scenario-file",type=str, default=os.environ.get('UNL_SCENARIO_FILE') if os.environ.get('UNL_SCENARIO_FILE') else None ,
                                help="Defines the scenario file to execute.") #default='./unl-manager/unlscenario.json',
    argparser.add_argument("-p","--publish-path",type=str, default=os.environ.get('UNL_PUBLISH_PATH') if os.environ.get('UNL_PUBLISH_PATH') else None ,
                                help="Defines the root of publish.") #default='./unl-manager/unls/',
    argparser.add_argument("-k","--keys-path",type=str,default=os.environ.get('VALIDATORS_KEYS_PATH') if os.environ.get('VALIDATORS_KEYS_PATH') else None ,
                                help="Defines the root path for the validators key pairs") #, default='./configfiles/'
    argparser.add_argument("-kf","--keys-file", type=str, help="Defines the keys-pair file used to sign the UNL",
                                default=os.environ.get('UNL_MANAGER_TOKEN') if os.environ.get('UNL_MANAGER_TOKEN') else None )#, default='./unl-generator-token.txt'
    argparser.add_argument("-c","--clean", help="Cleans up the generated files. NOTE: Do it only on clean testnet, otherwise UNLs won't be validated", action="store_true")
    gengroup=argparser.add_mutually_exclusive_group(required=False)
    gengroup.add_argument("-i","--generate-init-unl", help="Generates the UNL files for all the validators for the network initialization (testnet time=0)", action="store_true")
    gengroup.add_argument("-t","--generate-unl-on-time",type=int, help="Generates the UNL files for all the validators for the given time. Time should be defined in Ripple Epoch (secs since 01-01-2000)")

    argparser.add_argument("-vp","--visualization-path",type=str,default=os.environ.get('UNL_VISUALIZATION_PATH') if os.environ.get('UNL_VISUALIZATION_PATH') else None ,
                                help="Defines the root path for the vizualization output") 
    argparser.add_argument("-vf","--visualization-format",type=str,default=os.environ.get('UNL_VISUALIZATION_FORMAT') if os.environ.get('UNL_VISUALIZATION_FORMAT') else "dot" ,
                                help="Defines the format used for visualization (dot,JSON,mermaid)") 

    # ARGS_NOT_IN_CONFIG_FILE=set(['generate_init_unl','generate_unl_on_time','clean'])

    aa=argparser.parse_args()
    #print(aa) # prints all the arguments of the Argument parser
    
    config=None
    config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    config_section='daemon' if aa.daemon and aa.daemon==True else 'standalone'
    # print (config_section)

    if aa.config_file and os.path.exists(aa.config_file):
        print('Parsing section %s of the configuration file %s'%(config_section,aa.config_file))
        config.read(aa.config_file)
    else:
        print ('Configuration file does not exist!!!')
        print ('Running with other command line arguments options.')
        config.add_section(config_section)
    
    for arg in getCmdArgumentsOptions(argparser):
        # print('checking for arg',arg, type(arg))
        if (arg in aa) and (aa.__getattribute__(arg)!= None):
            # print(type(aa.__getattribute__(arg)))
            config[config_section][arg]=str(aa.__getattribute__(arg))
                
    # print(config.sections())
    # print(config)


    # Reading the UNL generator keys pair

    if 'keys_file' in config[config_section].keys():
        if os.path.exists(config[config_section]['keys_file']):
            vtoken=encodeUNL.parseValidatorTokenFile(config[config_section]['keys_file'])
            print(vtoken)
        else:
            print ("FATAL ERROR: keys file "+config[config_section]['keys_file']+" does not exist.")
            sys.exit(1)
    else:
        print("FATAL ERROR: \"keys_file\" is not set under "+config_section+" section of the configuration file.")
        sys.exit(1)
    
    
    # Reading the scenario file

    if 'scenario_file' in config[config_section].keys():
        if os.path.exists(config[config_section]['scenario_file']):
            msc=scutils.UNLScenario(scenario_fname=config[config_section]['scenario_file'])
            print (msc)
        else:
            print ("FATAL ERROR: scenario file "+config[config_section]['scenario_file']+" does not exist.")
            sys.exit(1)
    else:
        print("FATAL ERROR: \"scenario_file\" is not set under "+config_section+" section of the configuration file.")
        sys.exit(1)
    
    # Checking Publish Path for UNLs
    if 'publish_path' in config[config_section].keys():
        if os.path.exists(config[config_section]['publish_path']):
            # TODO: Create directory structure according to the scenario
            # os.makedirs(dirname,exist_ok=True)
            for v in msc.validators:
                os.makedirs(config[config_section]['publish_path']+'/unls/'+v,exist_ok=True)
            
        else:
            print ("FATAL ERROR: Publish path "+config[config_section]['publish_path']+" does not exist.")
            sys.exit(1)
    else:
        print("FATAL ERROR: \"publish_path\" is not set under "+config_section+" section of the configuration file.")
        sys.exit(1)
    

    # mscV=scutils.ScenarioVisualizer(msc)

    # mdotg=mscV.getUNLGraphAtTime(0)
    # mdotg.render('./testout.gv',view=True)

    #locking publish path
    process_lock=lockfile.LockFile(config[config_section]['pid_file'][:-4]+'.lock')
    # try:
    #     process_lock.acquire()
    # except lockfile.AlreadyLocked:
    #     print("Another UNL-manager process is running!!!")
    #     sys.exit(1)
    # except lockfile.LockFailed:
    #     print('Cannot create a lock file. Please check permissions.')
    #     sys.exit(1)
    # else:
    #     print("Process lockfile created!!!")


    # Checking for single-task options

    if ('generate_init_unl' in config[config_section].keys()) and (config[config_section].getboolean('generate_init_unl')):
        print ("Generating init UNL files for all the validators.")
        with process_lock:
            generateUNLsAtTime(msc,vtoken,config[config_section]['publish_path'],config[config_section]['keys_path'],0)

    elif ('generate_unl_on_time' in config[config_section].keys()) and (config[config_section].getint('generate_unl_on_time')>=0) :
        print ("Generating UNL files for all the validators on specific time", config[config_section]['generate_unl_on_time'] )
        with process_lock:
            generateUNLsAtTime(msc,vtoken,config[config_section]['publish_path'],config[config_section]['keys_path'],config[config_section].getint('generate_unl_on_time'))
        

    if "start" in config[config_section].keys() and config[config_section]["start"]:
        
        # Schedule the changes based on the scenario file.
        unl_manager_scheduler=sched.scheduler(time.time, time.sleep)
        start_time=time.time()
        # keep start_time in status file
        for st in msc.ordered_states:
            unl_manager_scheduler.enterabs(start_time+int(st),1,generateUNLsAtTime,argument=(msc,vtoken,config[config_section]['publish_path'],config[config_section]['keys_path'],int(st)))

        print ("Starting scheduler...")    
        with process_lock:
            unl_manager_scheduler.run()

        print("Scenario Finished!!!")
    elif "stop" in config[config_section].keys() and config[config_section]["stop"]:
        print("Stopping process...")
    elif "status" in config[config_section].keys() and config[config_section]["status"]:
        print ("Printing status...")
    elif "reload" in config[config_section].keys() and config[config_section]["reload"]:
        print("Reloading config files...")
    elif "restart" in config[config_section].keys() and config[config_section]["restart"]:
        print("Restarting process....")
    else:
        print ("No daemon action has been passed.")

    print("Bye bye!!!")
    

