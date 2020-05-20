#!/usr/bin/env python3
import argparse
import sys
import utils

argparser=argparse.ArgumentParser(description="Extracts the Trust Graph from a scenario file at the given time")
argparser.add_argument("-sc","--scenario-file", default='./unl-manager/unlscenario.json', type=str, help="Defines the UNL scenario file to be parsed")
# cmdgroup.set_defaults()

argparser.add_argument("-t","--time", default=0,type=int,
                            help="Defines the scenario time for which to generate the UNL.")
cgroup=argparser.add_mutually_exclusive_group(required=True)
cgroup.add_argument("-a","--all-nodes", default=False, help='Extracts the trust graph for all the nodes in one file', action="store_true")
cgroup.add_argument("-n","--node-list", type=str, nargs='*', help="Defines the nodes for which to generate the graph, in the same file")

argparser.add_argument("-of","--output-format", default='JSON', choices=['JSON','dot','mermaid'], type=str, help="Defines the output format.")
argparser.add_argument("-imf","--image-output-format", default='png', choices=['png','jpg','jpeg'], type=str, help="Defines the image output format.")
argparser.add_argument("-o","--output-file", type=str,default='./trustgraph.json',help="Defines the output file.")

aa=argparser.parse_args()
print (aa)