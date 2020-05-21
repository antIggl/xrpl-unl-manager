#!/usr/bin/env python3

import argparse
import sys
import utils
import scenario_utils as scutils


argparser=argparse.ArgumentParser(description="Manages the UNL files for a Ripple Testnet.")
cmdgroup=argparser.add_mutually_exclusive_group(required=False)
cmdgroup.add_argument("--start", help="Starts running the scenario file.", action="store_true")
cmdgroup.add_argument("--stop", help="Stops the running process on the same publish path", action="store_true")
cmdgroup.add_argument("--status", help="Prints the current state of the running process.", action="store_true")
# cmdgroup.set_defaults()

argparser.add_argument("-sc","--scenario-file",type=str, default='./unl-manager/unlscenario.json',
                            help="Defines the scenario file to execute.")
argparser.add_argument("-p","--publish-path",type=str, default='./unl-manager/unls/',
                            help="Defines the root of publish.")
argparser.add_argument("-k","--keys-path",type=str, default='./configfiles/',
                            help="Defines the root path for the validators key pairs")
argparser.add_argument("-c","--clean", help="Cleans up the generated files. NOTE: Do it only on clean testnet, otherwise UNLs won't be validated", action="store_true")
argparser.add_argument("-i","--generate-init-unl", help="Generates the UNL files for all the validators for the network initialization (testnet time=0)", action="store_true")
argparser.add_argument("-t","--generate-unl-on-time",type=int, help="Generates the UNL files for all the validators for the given time. Time should be defined in Ripple Epoch (secs since 01-01-2000)")

aa=argparser.parse_args()
print (aa)

# mfcont=scutils.readScenarioFile(aa.scenario_file)
#if __name__=='__main__':
msc=scutils.UNLScenario(scenario_fname=aa.scenario_file)
print (msc)

mscV=scutils.ScenarioVisualizer(msc)

mdotg=mscV.getUNLGraphAtTime(0)
mdotg.render('./testout.gv',view=True)