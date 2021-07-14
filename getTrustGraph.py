#!/usr/bin/env python3
import argparse
import sys
import utils
import scenario_utils as scutils
import json

argparser=argparse.ArgumentParser(description="Extracts the Trust Graph from a scenario file at the given time")
argparser.add_argument("-sc","--scenario-file", default='./unl-manager/unlscenario.json', type=str, help="Defines the UNL scenario file to be parsed")
# cmdgroup.set_defaults()

argparser.add_argument("-t","--time", default=0,type=int,
                            help="Defines the scenario time for which to generate the UNL.")
cgroup=argparser.add_mutually_exclusive_group(required=True)
cgroup.add_argument("-a","--all-nodes", default=False, help='Extracts the trust graph for all the nodes in one file', action="store_true")
cgroup.add_argument("-n","--node-list", type=str, nargs='*', help="Defines the nodes for which to generate the graph, in the same file")

argparser.add_argument("-of","--output-format", default='dot', choices=['JSON','dot','mermaid'], type=str, help="Defines the output format.")
# argparser.add_argument("-imf","--image-output-format", default='pdf', choices=['pdf','png','jpg','jpeg'], type=str, help="Defines the image output format.")
argparser.add_argument("-o","--output-file", type=str,default='./trustgraph.gv',help="Defines the output file.")

aa=argparser.parse_args()
print (aa)

msc=scutils.UNLScenario(scenario_fname=aa.scenario_file)
# print (msc)

mscV=scutils.ScenarioVisualizer(msc)

if aa.output_format == 'dot':
    if aa.all_nodes:
        mdotg=mscV.getUNLGraphAtTime(aa.time)
    else:
        mdotg=mscV.getValidatorsUNLGraphAtTime(aa.node_list,aa.time)
    mdotg.render(aa.output_file,view=True)
elif aa.output_format.upper()=='JSON':
    state_unls={}
    if aa.all_nodes:
        state_validators=msc.getStateAtTime(aa.time)['validators']
        for v,o in state_validators.items():
            state_unls[v]=o['unl']
    else:
        for v in aa.node_list:
            state_unls[v]=msc.getValidatorUNLAtTime(v,aa.time)
    
    with open(aa.output_file,'w') as f:
        json.dump(state_unls,f)
elif aa.output_format=='mermaid':
    if aa.all_nodes:
        mg=mscV.getUNLGraphAtTime(aa.time,type="mermaid")
    else:
        mg=mscV.getValidatorsUNLGraphAtTime(aa.node_list,aa.time, type="mermaid")
    
    with open(aa.output_file,'w') as f:
        f.write(mg)
    
else:
    print ("The output format is not supported.")

