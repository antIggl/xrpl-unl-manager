import json
import os
import threading
import concurrent
import utils
from graphviz import Digraph
import markdown

class UNLScenario():
    def __init__(self, scenario_fname=None, scenario_json=None):
        """Initializes the UNLscenario Object base on the file or the json object

        Keyword Arguments:
            scenario_fname {[type]} -- [description] (default: {None})
            scenario_json {[type]} -- [description] (default: {None})
        """
        fcont = None
        if scenario_fname and scenario_json:
            print("Only one of json or file can be used. Defaults to JSON")
            fcont = scenario_json
            self._load_scenario(fcont)
        elif scenario_fname:
            self.from_file(scenario_fname)
        elif scenario_json:
            fcont = scenario_json
            self._load_scenario(fcont)

    def from_file(self, scenario_fname):
        with open(scenario_fname, 'r') as f:
            fcont = json.load(f)
        self._load_scenario(fcont)

    def _load_scenario(self, scenario_json):
        for k, v in scenario_json.items():
            self.__setattr__(k, v)

        if not self.__getattribute__('states'):
            print("scenario file is not properly structured. No states attribute found.")
            return

        if "0" not in self.states.keys():
            # then search of initial_state state_id
            for i, stname in enumerate(self.states.keys()):
                if self.states[stname]['state_id'] == 'initial_state':
                    self.states["0"] = self.states[stname]
                    break
                if i >= len(scenario_json['states'].keys()):
                    print("Couldn't find the initial_state of the scenario.")
                    print("Please mark the initial_state of the scenario either by changing the tag to \"0\" or \n by setting the state_id attribute to \"initial_state\" . ")
                    return None

        # update states
        for prevstate, curstate in [(self.ordered_states[i-1], self.ordered_states[i]) for i in range(1, len(self.ordered_states))]:
            for mv in self.validators:
                if mv not in self.states[curstate]['validators'].keys():
                    self.states[curstate]['validators'][mv] = self.states[prevstate]['validators'][mv]

    @property
    def ordered_states(self):
        ret = list(self.__getattribute__('states').keys())
        ret.sort()
        return ret

    @property
    def validators(self):
        return list(self.states['0']['validators'].keys())

    def getStateAtTime(self,timestamp):
        """Returns the state for all the validators on the specified timestamp

        Arguments:
            timestamp {[type]} -- [description]
        """
        if len(self.ordered_states)==0:
            print (" NO STATES in the scenario file!!!")
            return None

        if len(self.ordered_states)==1:
            return self.states[self.ordered_states[0]]

        for curstate, nextstate in [(self.ordered_states[i-1], self.ordered_states[i]) for i in range(1, len(self.ordered_states))]:
            if not (curstate.isnumeric() and nextstate.isnumeric()):
                continue
            if int(nextstate)> timestamp:
                return self.states[curstate]
            elif int(nextstate)<= timestamp:
                return self.states[nextstate]
    
    def getValidatorUNLAtTime(self,validator,timestamp):
        state=self.getStateAtTime(timestamp)
        return state['validators'][validator]['unl']

    def getValidatorConnectionsAtTime(self,validator,timestamp):
        state=self.getStateAtTime(timestamp)
        return state['validators'][validator]['connected']


class ScenarioVisualizer():
    """
    Generates the script files for DOT digraph and mermaid graph tools
    """
    def __init__(self,scenario=None):
        self.scenario=scenario
    
    def load_from_file(self,scenario_fname):
        self.scenario=UNLScenario(scenario_fname=scenario_fname)
    
    def load_from_json(self, scenario_json):
        self.scenario=UNLScenario(scenario_json=scenario_json)

    def getUNLGraphAtTime(self,timestamp,type="dot"):
        """Returns the source code of the graph of type *type*

        Arguments:
            timestamp {[type]} -- [description]

        Keyword Arguments:
            type {str} -- [description] {"dot","mermaid"}(default: {"dot"})
        """
        if type=="dot":
            return self._getDOTUNLGraph(self.scenario.getStateAtTime(timestamp)['validators'])
        elif type=="mermaid":
            return self._getMermaidUNLGraph(self.scenario.getStateAtTime(timestamp)['validators'])
        else:
            return None
        
    def getValidatorsUNLGraphAtTime(self,validators_list,timestamp,type="dot"):
        """Returns the source code of the graph of type *type*

        Arguments:
            timestamp {[type]} -- [description]

        Keyword Arguments:
            type {str} -- [description] {"dot","mermaid"}(default: {"dot"})
        """
        state_validators=self.scenario.getStateAtTime(timestamp)['validators']
        gstate_validators={}
        for v in validators_list:
            if v in state_validators.keys():
                gstate_validators[v]=state_validators[v]
        
        if type=="dot":
            return self._getDOTUNLGraph(gstate_validators)
        elif type=="mermaid":
            return self._getMermaidUNLGraph(gstate_validators)
        else:
            return None
        
    def _getMermaidUNLGraph(self,validators_state:dict):
        """Generates the Mermaid script that plots the UNL graph

        Arguments:
            validators_state {dict} -- [description]
        """
        #TODO: use markdown and md_mermaid
        graphTemplate="""
            Some text.

            ​~~~mermaid
            graph TB
            <edges>
            ​~~~
            """
        medges=""
        for v,o in validators_state.items():
            for pn in o['unl']:
                medges+="{0} --> {1}\n".format(v,pn)

        graphText=graphTemplate.replace("<edges>",medges)
        html = markdown.markdown(graphText, extensions=['md_mermaid'])

        print(html)
        return html

    def _getDOTUNLGraph(self,validators_state:dict):
        """Generates the DOT script that plots the Digraph

        Arguments:
            validators_state {dict} -- [description]
        """
        mdot=Digraph()
        for v,o in validators_state.items():
            mdot.node(v,v)
            for pn in o['unl']:
                mdot.edge(v,pn)
        
        return mdot

# def readScenarioFile(fname):
#     with open(fname, 'r') as f:
#         fcont = json.load(f)

#     # print(fcont)
#     scenarioStates_TimeOrdered = list(fcont['states'].keys())
#     scenarioStates_TimeOrdered.sort()

#     if "0" not in scenarioStates_TimeOrdered:
#         # then search of initial_state state_id
#         for i, stname in enumerate(scenarioStates_TimeOrdered):
#             if fcont['states'][stname]['state_id'] == 'initial_state':
#                 fcont['states']["0"] = fcont['states'][stname]
#                 break
#             if i >= len(scenarioStates_TimeOrdered):
#                 print("Couldn't find the initial_state of the scenario.")
#                 print("Please mark the initial_state of the scenario either by changing the tag to \"0\" or \n by setting the state_id attribute to \"initial_state\" . ")
#                 return None
#     return fcont
