# XRPL UNL Manager
Set of scripts to encode/decode and manage Unique Node Lists for XRPL testnet validators.

***IT'S STILL UNDER HEAVY DEVELOPMENT***

## How it works
These scripts are used to execute a scenario of UNL changes in a XRPL Testnet.
* *unl_manager.py* : can run as a system daemon or standalone. It runs in a loop an executes the UNL changes for each validator as it is defined in the scenario file.
      When another *unl_manager.py* process is running in the same *publish_path*, it can  print the status or stop the running process.
      It also maintains a directory tree in the publish_path that can be served by any Web server.
* *decodeUNL.py* : decodes,validates and prints a UNL file or a UNL as it has been retrieved by a URL
* *encodeUNL.py* : encodes and signs a UNL file for the given list of validators
* *getTrustGraph.py* : parses the scenario file and extracts the connections graph in *mermaid* or *dot* format, that can be then used to visualize the graph.

At last, we include a *docker-compose* file that launches a *nginx* web server container and a *python* container running the *unl_manager.py* daemon.

## Requirements
* Python 3
* ripple-lib for python
* base64, base58
* Docker

```
pip install -r ./requirements.txt
```
## Running scripts in a Docker container

The following command launches a Docker container with an interractive shell, after it installing the python modules using ```requirements.txt``` file. 
```bash
SRC_PATH=$(realpath relative/path/to/srcdir) ./docker/launch_container.sh
```
In case Docker daemon won't find the ```python:3``` image locally, it will pull it from Dockerhub.
 
The initialization script that runs before the interractive shell can be found in ```./docker/init_container.sh```.

## Scripts command line arguments and configuration

### UNL manager script
```
usage: unl_manager.py [-h] [--start | --stop | --status] [-sc SCENARIO_FILE]
                      [-p PUBLISH_PATH] [-k KEYS_PATH] [-c] [-i]
                      [-t GENERATE_UNL_ON_TIME]

Manages the UNL files for a XRPL Testnet.

optional arguments:
  -h, --help            show this help message and exit
  --start               Starts running the scenario file.
  --stop                Stops the running process on the same publish path
  --status              Prints the current state of the running process.
  -sc SCENARIO_FILE, --scenario-file SCENARIO_FILE
                        Defines the scenario file to execute.
  -p PUBLISH_PATH, --publish-path PUBLISH_PATH
                        Defines the root of publish.
  -k KEYS_PATH, --keys-path KEYS_PATH
                        Defines the root path for the validators key pairs
  -c, --clean           Cleans up the generated files. NOTE: Do it only on
                        clean testnet, otherwise UNLs won't be validated
  -i, --generate-init-unl
                        Generates the UNL files for all the validators for the
                        network initialization (testnet time=0)
  -t GENERATE_UNL_ON_TIME, --generate-unl-on-time GENERATE_UNL_ON_TIME
                        Generates the UNL files for all the validators for the
                        given time. Time should be defined in XRPL Epoch
                        (secs since 01-01-2000)
```

### Decode / Encode UNL
```
usage: decodeUNL.py [-h] (-f FILE | -u URL) [-v] [-pb | -pl | -pv]
                    [-o OUTPUT_FILE]

Decodes a XRPL UNL either from a file or from a URL

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Defines the UNL file to be parsed
  -u URL, --url URL     Defines the URL to retrieve the UNL file
  -v, --validate        Enables the UNL validation during the decoding
  -pb, --print-blob     Prints the UNL blob JSON object
  -pl, --print-validators-list
                        Prints the validators public keys list only
  -pv, --print-validators
                        Prints the validators objects list only
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Defines the output file.
```

```
usage: encodeUNL.py [-h] [-f LIST_FILE] [-v VERSION] [-kf KEYS_FILE]
                    [-kp VALIDATORS_KEYS_PATH] [-o OUTPUT_FILE]

Encodes a XRPL UNL from a file containing either a JSON list or line-
separated validator names

optional arguments:
  -h, --help            show this help message and exit
  -f LIST_FILE, --list-file LIST_FILE
                        Defines the UNL file to be parsed
  -v VERSION, --version VERSION
                        Defines the version of the UNL.
  -kf KEYS_FILE, --keys-file KEYS_FILE
                        Defines the keys-pair file used to sign the UNL
  -kp VALIDATORS_KEYS_PATH, --validators-keys-path VALIDATORS_KEYS_PATH
                        Defines the root path for the validators
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Defines the output file.

```

### Extract Trust Graph
```
usage: getTrustGraph.py [-h] [-sc SCENARIO_FILE] [-t TIME]
                        (-a | -n [NODE_LIST [NODE_LIST ...]])
                        [-of {JSON,dot,mermaid}] [-imf {png,jpg,jpeg}]
                        [-o OUTPUT_FILE]

Extracts the Trust Graph from a scenario file at the given time

optional arguments:
  -h, --help            show this help message and exit
  -sc SCENARIO_FILE, --scenario-file SCENARIO_FILE
                        Defines the UNL scenario file to be parsed
  -t TIME, --time TIME  Defines the scenario time for which to generate the
                        UNL.
  -a, --all-nodes       Extracts the trust graph for all the nodes in one file
  -n [NODE_LIST [NODE_LIST ...]], --node-list [NODE_LIST [NODE_LIST ...]]
                        Defines the nodes for which to generate the graph, in
                        the same file
  -of {JSON,dot,mermaid}, --output-format {JSON,dot,mermaid}
                        Defines the output format.
  -imf {png,jpg,jpeg}, --image-output-format {png,jpg,jpeg}
                        Defines the image output format.
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Defines the output file.

```
## Example
TODO:

## Contributors
* Antonios Inglezakis (@antiggl)
* Alloy Networks (@alloyxrp)
