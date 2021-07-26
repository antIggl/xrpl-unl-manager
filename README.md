# XRPL UNL Manager
Set of scripts to encode/decode and manage Unique Node Lists for XRPL testnet validators.

**Update 14/07/2021 :** 
* Not released yet, but most of the parts are working.
* Extensive testing is required.
* Documentation and release as python package are in my plans too.
 
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
* cryptography 3.3.2
* ECpy
* base64
* base58 >=2.1.0
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
usage: unl_manager.py [-h]
                      [--start | --stop | --status | --reload | --restart]
                      [-d] [-sf STATUS_FILE] [-pid PID_FILE]
                      [-workdir WORKING_DIRECTORY] [-log LOG_FILE]
                      [-conf CONFIG_FILE] [-sc SCENARIO_FILE]
                      [-p PUBLISH_PATH] [-k KEYS_PATH] [-kf KEYS_FILE] [-c]
                      [-i | -t GENERATE_UNL_ON_TIME] [-vp VISUALIZATION_PATH]
                      [-vf VISUALIZATION_FORMAT]

Manages the UNL files for a Ripple Testnet.

optional arguments:
  -h, --help            show this help message and exit
  --start               Starts running the scenario file.
  --stop                Stops the running process on the same publish path
  --status              Prints the current state of the running process.
  --reload              Reloads configuration from files
  --restart             Restarts Daemon process.
  -d, --daemon          Runs as a daemon.
  -sf STATUS_FILE, --status-file STATUS_FILE
                        Defines the status file.
  -pid PID_FILE, --pid-file PID_FILE
                        Defines the pid locking file.
  -workdir WORKING_DIRECTORY, --working-directory WORKING_DIRECTORY
                        Defines the working directory.
  -log LOG_FILE, --log-file LOG_FILE
                        Defines the working directory.
  -conf CONFIG_FILE, --config-file CONFIG_FILE
                        Defines the configuration file.
  -sc SCENARIO_FILE, --scenario-file SCENARIO_FILE
                        Defines the scenario file to execute.
  -p PUBLISH_PATH, --publish-path PUBLISH_PATH
                        Defines the root of publish.
  -k KEYS_PATH, --keys-path KEYS_PATH
                        Defines the root path for the validators key pairs
  -kf KEYS_FILE, --keys-file KEYS_FILE
                        Defines the keys-pair file used to sign the UNL
  -c, --clean           Cleans up the generated files. NOTE: Do it only on
                        clean testnet, otherwise UNLs won't be validated
  -i, --generate-init-unl
                        Generates the UNL files for all the validators for the
                        network initialization (testnet time=0)
  -t GENERATE_UNL_ON_TIME, --generate-unl-on-time GENERATE_UNL_ON_TIME
                        Generates the UNL files for all the validators for the
                        given time. Time should be defined in Ripple Epoch
                        (secs since 01-01-2000)
  -vp VISUALIZATION_PATH, --visualization-path VISUALIZATION_PATH
                        Defines the root path for the vizualization output
  -vf VISUALIZATION_FORMAT, --visualization-format VISUALIZATION_FORMAT
                        Defines the format used for visualization
                        (dot,JSON,mermaid)
```

### Decode / Encode UNL
```
usage: decodeUNL.py [-h] (-f FILE | -u URL) [-v]
                    [-praw | -pb | -prb | -pl | -pv | -pm | -ps]
                    [-o OUTPUT_FILE] [-ro RAW_OUTPUT_FILE]

Decodes an XRP Ledger UNL either from a file or from a URL

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Defines the UNL file to be parsed
  -u URL, --url URL     Defines the URL to retrieve the UNL file
  -v, --verify          Enables the UNL verification with manifest and blob
                        signatures during the decoding
  -praw, --print-raw    Prints the UNL JSON as received
  -pb, --print-blob     Prints the UNL blob JSON object
  -prb, --print-raw-blob
                        Prints the UNL blob RAW
  -pl, --print-validators-list
                        Prints the validators public keys list only
  -pv, --print-validators
                        Prints the validators objects list only
  -pm, --print-manifest
                        Prints the validators list manifest
  -ps, --print-signature
                        Prints the validators list signature
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Defines the output file.
  -ro RAW_OUTPUT_FILE, --raw-output-file RAW_OUTPUT_FILE
                        Defines the raw output file, as received.

```

```
usage: encodeUNL.py [-h] [-f LIST_FILE] [-blf BLOBLIST_FILE] [-bf BLOB_FILE]
                    [-v VERSION] [-xd EXPIRE_DATE] [-kf KEYS_FILE]
                    [-kp VALIDATORS_KEYS_PATH] [-o OUTPUT_FILE]

Encodes a XRP Ledger UNL from a file containing either a JSON list or line-
separated validator names

optional arguments:
  -h, --help            show this help message and exit
  -f LIST_FILE, --list-file LIST_FILE
                        Defines the UNL file to be parsed. It needs the
                        validators-keys-path
  -blf BLOBLIST_FILE, --bloblist-file BLOBLIST_FILE
                        Defines the UNL blob list file to be parsed. -
                        Expiration date and sequence can be set separately
  -bf BLOB_FILE, --blob-file BLOB_FILE
                        Defines the UNL blob file to be parsed - Expiration
                        date and sequence cannot be set
  -v VERSION, --version VERSION
                        Defines the version/sequence of the UNL.
  -xd EXPIRE_DATE, --expire-date EXPIRE_DATE
                        Sets the expiration date of the generated UNL.
                        (format: YYYYMMDDhhmmss). Defaults to 1 year since
                        now.
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
## Examples
* Examples of input files to *encodeUNL.py* are in *examples/* directory.


**Get the UNL list from *https://vl.ripple.com*, validate it and print the list for validators public keys.**
```bash
$ ./decodeUNL.py -u https://vl.ripple.com -v -pl
[b'nHBtDzdRDykxiuv7uSMPTcGexNm879RUUz5GW4h1qgjbtyvWZ1LE', b'nHUzum747yqip3HWSgzSNHNMjmLUqhroNVWidSRTREswEVhKNQEM', b'nHUon2tpyJEHHYGmxqeGu37cvPYHzrMtUNQFVdCgGNvEkjmCpTqK', b'nHU2Y1mLGDvTbc2dpvpkQ16qdeTKv2aJwGJHFySSB9U3jkTmj4CA', b'nHDDasc9BHNB99PW8KUduS8Phqg8NPUmjufzMU6HGGDMUH2xNpPh', b'nHUUrjuEMtvzzTsiW2xKinUt7Jd83QFqYgfy3Feb7Hq1EJyoxoSz', b'nHUkp7WhouVMobBUKGrV5FNqjsdD9zKP5jpGnnLLnYxUQSGAwrZ6', b'nHU95JxeaHJoSdpE7R49Mxp4611Yk5yL9SGEc12UDJLr4oEUN4NT', b'nHUCCckfXVBdoounaU7JVnfdPdMXEeetwH8VdCBXD996BaVZ8WdJ', b'nHUFzgC9fDw2MEDaiv9JMdBFhtJ6DMKoUCpS8gPGi6tkfbqmTyis', b'nHBidG3pZK11zQD6kpNDoAhDxH6WLGui6ZxSbUx7LSqLHsgzMPec', b'nHBgiH2aih5JoaL3wbiiqSQfhrC21vJjxXoCoD2fuqcNbriXsfLm', b'nHUcNC5ni7XjVYfCMe38Rm3KQaq27jw7wJpcUYdo4miWwpNePRTw', b'nHUXeusfwk61c4xJPneb9Lgy7Ga6DVaVLEyB29ftUdt9k2KxD6Hw', b'nHUd8g4DWm6HgjGTjKKSfYiRyf8qCvEN1PXR7YDJ5QTFyAnZHkbW', b'nHB8QMKGt9VB4Vg71VszjBVQnDW3v3QudM4DwFaJfy96bj4Pv9fA', b'nHDwHQGjKTz6R6pFigSSrNBrhNYyUGFPHA75HiTccTCQzuu9d7Za', b'nHUpJSKQTZdB1TDkbCREMuf8vEqFkk84BcvZDhsQsDufFDQVajam', b'nHUVPzAmAmQ2QSc4oE1iLfsGi17qN2ado8PhxvgEkou76FLxAz7C', b'nHUT6Xa588zawXVdP2xyYXc87LQFm8uV38CxsVzq2RoQJP8LXpJF', b'nHB5kpvUaEpvCtwu31fMf6dTuuCNnWRctWrV3UEZ9rbtPdpvbUvJ', b'nHULqGBkJtWeNFjhTzYeAsHA3qKKS7HoBh8CV3BAGTGMZuepEhWC', b'nHUfPizyJyhAJZzeq3duRVrZmsTZfcLn7yLF5s2adzHdcHMb9HmQ', b'nHUFE9prPXPrHcG3SkwP1UzAQbSphqyQkQK9ATXLZsfkezhhda3p', b'nHUFCyRCrUjvtZmKiLeF8ReopzKuUoKeDeXo3wEUBVSaawzcSBpW', b'nHUnhRJK3csknycNK5SXRFi8jvDp3sKoWvS9wKWLq1ATBBGgPBjp', b'nHDB2PAPYqF86j9j3c6w1F1ZqwvQfiWcFShZ9Pokg9q4ohNDSkAz', b'nHDH7bQJpVfDhVSqdui3Z8GPvKEBQpo6AKHcnXe21zoD4nABA6xj', b'nHUpcmNsxAw47yt2ADDoNoQrzLyTJPgnyq16u6Qx2kRPA17oUNHz', b'nHUryiyDqEtyWVtFG24AAhaYjMf9FRLietbGzviF3piJsMm9qyDR', b'nHUED59jjpQ5QbNhesXMhqii9gA8UfbBmv3i5StgyxG98qjsT4yn', b'nHDDE4Y3z5EE2VDDYrzheYQ4xC3F29SJsKT4dqhX4iyTLhuWgZnp', b'nHUvzia57LRXr9zqnYpyFUFeKvis2tqn4DkXBVGSppt5M4nNq43C', b'nHUcQnmEbCNq4uhntFudzfrZV8P5WLoBrR5h3R9jAd621Aaz1pSy', b'nHUERu1nWxv2PAtFAPKWuy6gSVhsMhSY8A52m8P7R2ZwrH7upuym', b'nHUq9tJvSyoXQKhRytuWeydpPjvTz3M9GfUpEqfsg9xsewM7KkkK', b'nHUbgDd63HiuP68VRWazKwZRzS61N37K3NbfQaZLhSQ24LGGmjtn']
Verified:  True
```

**Sign a copy of *https://vl.ripple.com* UNL list**
```bash
$ ./decodeUNL.py -u https://vl.ripple.com -pb > vl_ripple_com_blob.json

$ ./encodeUNL.py -bf ./vl_ripple_com_blob.json -kf ./unl-validator-token.txt -o ./mysigned_vl_ripple_com_unl.json
Finished!!!
$ $ ./decodeUNL.py -f ./mysigned_vl_ripple_com_unl.json -v -pl
[b'nHBtDzdRDykxiuv7uSMPTcGexNm879RUUz5GW4h1qgjbtyvWZ1LE', b'nHUzum747yqip3HWSgzSNHNMjmLUqhroNVWidSRTREswEVhKNQEM', b'nHUon2tpyJEHHYGmxqeGu37cvPYHzrMtUNQFVdCgGNvEkjmCpTqK', b'nHU2Y1mLGDvTbc2dpvpkQ16qdeTKv2aJwGJHFySSB9U3jkTmj4CA', b'nHDDasc9BHNB99PW8KUduS8Phqg8NPUmjufzMU6HGGDMUH2xNpPh', b'nHUUrjuEMtvzzTsiW2xKinUt7Jd83QFqYgfy3Feb7Hq1EJyoxoSz', b'nHUkp7WhouVMobBUKGrV5FNqjsdD9zKP5jpGnnLLnYxUQSGAwrZ6', b'nHU95JxeaHJoSdpE7R49Mxp4611Yk5yL9SGEc12UDJLr4oEUN4NT', b'nHUCCckfXVBdoounaU7JVnfdPdMXEeetwH8VdCBXD996BaVZ8WdJ', b'nHUFzgC9fDw2MEDaiv9JMdBFhtJ6DMKoUCpS8gPGi6tkfbqmTyis', b'nHBidG3pZK11zQD6kpNDoAhDxH6WLGui6ZxSbUx7LSqLHsgzMPec', b'nHBgiH2aih5JoaL3wbiiqSQfhrC21vJjxXoCoD2fuqcNbriXsfLm', b'nHUcNC5ni7XjVYfCMe38Rm3KQaq27jw7wJpcUYdo4miWwpNePRTw', b'nHUXeusfwk61c4xJPneb9Lgy7Ga6DVaVLEyB29ftUdt9k2KxD6Hw', b'nHUd8g4DWm6HgjGTjKKSfYiRyf8qCvEN1PXR7YDJ5QTFyAnZHkbW', b'nHB8QMKGt9VB4Vg71VszjBVQnDW3v3QudM4DwFaJfy96bj4Pv9fA', b'nHDwHQGjKTz6R6pFigSSrNBrhNYyUGFPHA75HiTccTCQzuu9d7Za', b'nHUpJSKQTZdB1TDkbCREMuf8vEqFkk84BcvZDhsQsDufFDQVajam', b'nHUVPzAmAmQ2QSc4oE1iLfsGi17qN2ado8PhxvgEkou76FLxAz7C', b'nHUT6Xa588zawXVdP2xyYXc87LQFm8uV38CxsVzq2RoQJP8LXpJF', b'nHB5kpvUaEpvCtwu31fMf6dTuuCNnWRctWrV3UEZ9rbtPdpvbUvJ', b'nHULqGBkJtWeNFjhTzYeAsHA3qKKS7HoBh8CV3BAGTGMZuepEhWC', b'nHUfPizyJyhAJZzeq3duRVrZmsTZfcLn7yLF5s2adzHdcHMb9HmQ', b'nHUFE9prPXPrHcG3SkwP1UzAQbSphqyQkQK9ATXLZsfkezhhda3p', b'nHUFCyRCrUjvtZmKiLeF8ReopzKuUoKeDeXo3wEUBVSaawzcSBpW', b'nHUnhRJK3csknycNK5SXRFi8jvDp3sKoWvS9wKWLq1ATBBGgPBjp', b'nHDB2PAPYqF86j9j3c6w1F1ZqwvQfiWcFShZ9Pokg9q4ohNDSkAz', b'nHDH7bQJpVfDhVSqdui3Z8GPvKEBQpo6AKHcnXe21zoD4nABA6xj', b'nHUpcmNsxAw47yt2ADDoNoQrzLyTJPgnyq16u6Qx2kRPA17oUNHz', b'nHUryiyDqEtyWVtFG24AAhaYjMf9FRLietbGzviF3piJsMm9qyDR', b'nHUED59jjpQ5QbNhesXMhqii9gA8UfbBmv3i5StgyxG98qjsT4yn', b'nHDDE4Y3z5EE2VDDYrzheYQ4xC3F29SJsKT4dqhX4iyTLhuWgZnp', b'nHUvzia57LRXr9zqnYpyFUFeKvis2tqn4DkXBVGSppt5M4nNq43C', b'nHUcQnmEbCNq4uhntFudzfrZV8P5WLoBrR5h3R9jAd621Aaz1pSy', b'nHUERu1nWxv2PAtFAPKWuy6gSVhsMhSY8A52m8P7R2ZwrH7upuym', b'nHUq9tJvSyoXQKhRytuWeydpPjvTz3M9GfUpEqfsg9xsewM7KkkK', b'nHUbgDd63HiuP68VRWazKwZRzS61N37K3NbfQaZLhSQ24LGGmjtn']
Verified:  True
```

**Sign a copy of *https://vl.ripple.com* UNL list, set sequence and new expire date**
```bash
$ ./decodeUNL.py -u https://vl.ripple.com -pv > ./vl_ripple_com_bloblist.json 
$ ./encodeUNL.py -blf ./vl_ripple_com_bloblist.json -kf ./unl-validator-token.txt -o ./mysigned_vl_ripple_com_unl.json -xd 20220202000000 -v 10
Finished!!!
$ ./decodeUNL.py -f ./mysigned_vl_ripple_com_unl.json -v -pb
{"validators": [{"validation_public_key": "ED45E80A04D79CB9DF00AEBD86DCDC1686D6419EA9E5E0E71F1A817E08B5076A55", "manifest": "JAAAAAFxIe1F6AoE15y53wCuvYbc3BaG1kGeqeXg5x8agX4ItQdqVXMhAxZo157pcB9de6Smk7hoK3wNCAr4aFZtfAPi7CE4mNJldkcwRQIhALlVjXCfiy/mtXBWsNt77t4jKcNEBpRV8zv+SpU5lCh0AiBa8vo8xxpviYlf4zdG+nQhB2OgfkQZZPMHOt7CaXzXgXASQL8O5p083mg4KKL8uZfMaUqdgzuJ0Gta1lyUWPctTPCxY135XwK+nJAdFsIUFNJ9MPjnpCmSjYVzVa6M5/nAcAI="}, {"validation_public_key": "EDD8C88642795CE69C5B780E01702C370F9507D0B64433F17EFE70F2637A40ADB7", "manifest": "JAAAAAFxIe3YyIZCeVzmnFt4DgFwLDcPlQfQtkQz8X7+cPJjekCtt3MhAnFfr+r9BXdsXE/cBlJMyd/XsO1A5XEYCctrsvLEX+DmdkcwRQIhANRcRMg9SAXoaOvHDZ2av9RzEaZaVENfQiVgsi+Ox3F0AiB2snSIOm6c4/inbtU0UmWLQTzuwkOdUFPIB8Ax8dmGuHASQMUIfXMj96kcFTSJnMFC/mW/AQ8bKXkFrrk0CUTFFKweEjTq+STrFi6qLL2MT7nveGxsXBCgztjc0qGas9KFWgM="}, {"validation_public_key": "EDBDEB901F7C75D0E20C6C42AF03BE0DA40377AF1939A18B3CB3679661DD5F9F74", "manifest": "JAAAAAFxIe2965AffHXQ4gxsQq8Dvg2kA3evGTmhizyzZ5Zh3V+fdHMhAg3cyKNPMPqKgR7kIi7c/8GL/YgdBtg4mSAWvwmaevVGdkYwRAIgWzG8GqYg3YpwDs8xXa9XqLHss76KT2uAHRhUXFVUqCQCIG2EvbFKnxezRd9cpPHSt32HXK+P4+aL3p2+vqlCxRR9cBJAboXTmYTayocA3zf9dWEXtyaeOGC1k5WdYURzPleevvalR4xVoXzs38iGPxFr/pA9nL+M4duu0GKCHlVir+fBAg=="}, {"validation_public_key": "EDA17871E72B0C570AC4345C60CF02AFBBB740A631B7AD0E1E573216574D9AEA02", "manifest": "JAAAAAFxIe2heHHnKwxXCsQ0XGDPAq+7t0CmMbetDh5XMhZXTZrqAnMhAojyuzgtreQkxQj8prHxOsbDcF5fu4XXb0KxEL/Pq5HhdkcwRQIhANfPDLZP47aCWwt5kBnp75BuuCgp9c4BfJPd66SFCw61AiAJvegBvvPIrec+XOSzKRfi5uuXWxtl9Eyr2aPBYXvbRHASQMULYEo7beRfoUCnjk1sTYyY91tLIGLgnnaWXhUm80+zs5IGegk8qijKAtBOMuBC71lAB4KhJc+dB2rpMOFc5gw="}, {"validation_public_key": "EDF46EE27AD0E1A714AFECDA816EAB7114614FCB92D0CB4D97B6A88ED43434AFC9", "manifest": "JAAAAAFxIe30buJ60OGnFK/s2oFuq3EUYU/LktDLTZe2qI7UNDSvyXMhAw0ATWjVTt4FfeKO7kv6fFgd/go2+d5BSyUcURmRWnTtdkcwRQIhAMwOgDec7QYYNngspg90wEvVbsoh2ux14RPTw+GHaXNlAiALgfEsz+AF4eyX/Y5i44VrFjFFIMWUfOZaQJtsxteM1XASQLOaF0t2ZpqVKd8JESQVY+zU567iAAG2amTPZx95875S9A6Pl+kH5TGHMAeWjgWSqfh3m2HBJX7NIcXb98vy9AA="}, {"validation_public_key": "ED6E4C41E59FFBEB51726E54468502FE6437238FA78EA51634E7BF0D09171AEE8F", "manifest": "JAAAAAFxIe1uTEHln/vrUXJuVEaFAv5kNyOPp46lFjTnvw0JFxruj3MhAuztGWb/Oi1/V5m5dujWr9HmbKRyK4XYk+kmuFPSgAFrdkYwRAIgfQ+BgXX6QblZy4H05o7GPSIwqS7QQRUW7dqF54IAiiMCIH4XfLw956iEaoxZOk7Kctin2X9hMfaLN7wys9yAUFoZcBJAueEi84XR3Ll1GLJWanW1g1MdUj/0PAxJbw6EEQRuG3zdnuRHNXld6UZAbIkVcP0ztfqulBzjbcsLDOKFEicSBg=="}, {"validation_public_key": "EDB6FC8E803EE8EDC2793F1EC917B2EE41D35255618DEB91D3F9B1FC89B75D4539", "manifest": "JAAAAAFxIe22/I6APujtwnk/HskXsu5B01JVYY3rkdP5sfyJt11FOXMhA8VdvHFyScByQGTYNGeOvB0+67gWaqefcfvRk5+KwgV1dkYwRAIgZFulO/AiMoczng6i/4BkfzT7j9lxF4PP1ufgrOQaJ8sCIBX/E8Zbpn7tWqgAyNyWpVPkhFmaUMqEry8WoUT1fdGQcBJAv51RqJxgg/VrnrZwiLK2Dc0CKbiLPO5HJ4ZMsjdPT2gRc97rWkAXuV2L6PNFO59xyuoaZmSMlZYvqSGPpfF7Bw=="}, {"validation_public_key": "ED691303992FEC64E6BC4BACD36AE6E5AEDC23F2861B6D8EFB9FD77EE3EADE3435", "manifest": "JAAAAAFxIe1pEwOZL+xk5rxLrNNq5uWu3CPyhhttjvuf137j6t40NXMhAi2AXJQgo/JuW3r7f/6CcVsGN1YmIj11GiIESHBnQSk8dkcwRQIhANCDEQymrd6veT3ouacF6fhBr5wLw3GmXg1rMCLVvBzZAiA8uWQ+tqd46WmfBexjSBQ2Jd6UAGdrHvjcCQ2ZgSooCnASQFkHl+D7/U3WByYP384+pcFDf2Gi4WIRHVTo58cqdk5CDiwc1T0rDoLhmo41a3f+dsftfwR4aMmwFcPXLnrjrAI="}, {"validation_public_key": "EDAD16667F0185DDBB7FA65B22F4B7D310BF5C3E2D9B823FB06A3A41AF8AC83BC1", "manifest": "JAAAAAFxIe2tFmZ/AYXdu3+mWyL0t9MQv1w+LZuCP7BqOkGvisg7wXMhAqweE3PIS3E44KhMqKjKtbkBe8H8GbiuoAXAYDRoVRHodkYwRAIgagGkXtowUybdltKojv0lvvflrlQ9IRnPOjekF60iHzgCICg6ZocIMzkUuvO91BEormIWmX4G/MGT2zro6I/PvB8XcBJAcJLXkt/w/kcwEvNiZmi2i2nMn1wiP3LS9NJjBPju8KFLAMg0O9ydQT67U/ALYOeTPTO2/i2Yw9OSlibtqhgzDA=="}, {"validation_public_key": "EDC245027A52EE5318095598EC3AB65FF4A3B9F9428E10B2F3C6F39DE15A15C90A", "manifest": "JAAAAAFxIe3CRQJ6Uu5TGAlVmOw6tl/0o7n5Qo4QsvPG853hWhXJCnMhA/8/9rKUdA61j/fIEP/cqLpxBlmIhP2rg1d7NaEPyKV+dkcwRQIhAIxE0M/FJ50vfZW6fPpy4yCZumY9n0obrOojUkjm55a0AiBj56O0MpopGoY9HxC/+4wNO36Ho7E9CQeHsnKreDdsAXASQIYUd81jbiVUlET4dGoG2p+cf+2GqEXX5fJMSSyX/qe0XfR4cO+4qlgmjMQdCRDBWABHVvdN/yZyi/rL2c+WrQc="}, {"validation_public_key": "ED4246AA3AE9D29863944800CCA91829E4447498A20CD9C3973A6B59346C75AB95", "manifest": "JAAAAAFxIe1CRqo66dKYY5RIAMypGCnkRHSYogzZw5c6a1k0bHWrlXMhAkm1lz0c8QXWfJ9b1vB72dLabw8wYId8MtnpsHHBEC8pdkYwRAIgQlb6HJ53hsTAfVid+AOdBVvMF7rahIKNLBHUgn52zBECIGLUqFu8a1AAHRJcVonKYEnmhJwbCXLn+je7na1WD1/ocBJAE4vfvrGSmZC2uAUGmM5dIBtoSgEUey+2VleDYEsce94txYcjR8Z7QLNaliD8w/bD5/hvYQ8meV1Wg1jJFNe0CA=="}, {"validation_public_key": "ED2C1468B4A11D281F93EF337C95E4A08DF0000FDEFB6D0EA9BC05FBD5D61A1F5A", "manifest": "JAAAAAFxIe0sFGi0oR0oH5PvM3yV5KCN8AAP3vttDqm8BfvV1hofWnMhAkMUmCD2aPmgFDDRmimvSicSIScw6YNr42Dw4RAdwrOAdkcwRQIhAJFOHMg6qTG8v60dhrenYYk6cwOaRXq0RNmLjyyCiz5lAiAdU0YkDUJQhnN8Ry8s+6zTJLiNLbtM8oO/cLnurVpRM3ASQGALarHAsJkSZQtGdM2AaR/joFK/jhDU57+l+RSYjri/ydE20DaKanwkMEoVlBTg7lX4hYjEnmkqo73wIthLOAQ="}, {"validation_public_key": "EDA54C85F91219FD259134B6B126AD64AE7204B81DD4052510657E1A5697246AD2", "manifest": "JAAAAHlxIe2lTIX5Ehn9JZE0trEmrWSucgS4HdQFJRBlfhpWlyRq0nMhAuAm/kLuTHmcOaDruJBjKjWOp1UtGuO8CICtRp4vo4HGdkcwRQIhAP1SPcKuMlGGDe5rcQAf1x/BmnVtBIG4Hv9US5b/GyZCAiA+03cZu9+EBqSZueF5lAUSPY/HRfL7pqxwn89fS4AFA3ASQJq+QRUP+aXB2iMxZrEajySxGs7CNpucyptWV0bnaq7ilnfUCvMlfszq5mV0rahB89C2zAnf7FjH0Cx0BML29QA="}, {"validation_public_key": "ED9AE4F5887BA029EB7C0884486D23CF281975F773F44BD213054219882C411CC7", "manifest": "JAAAAAFxIe2a5PWIe6Ap63wIhEhtI88oGXX3c/RL0hMFQhmILEEcx3MhAmG2zgv8FBZsZJU8aPapwo9cIqQv4/MSS1oVA5eVMiwLdkYwRAIgF+LOe4eY0gp9ttqh2gnv+z75OqLyOQMpGPALgm+NtOsCICDXBZVPtprmBDkBJkPFSnE55D9eKYRH8z/iY1EtpNplcBJAADEWGVT80Owhd1lh2JsU/oZlmeNF5WN7YvlB8llExaRKEVC+GW9Wg+iNIQ3rmV7P8aNaVuaabG00fOgkgzNhDw=="}, {"validation_public_key": "EDA8D29F40CEB28995617641A3BC42692E1DE883214F612FBB62087A148E5F6F9A", "manifest": "JAAAAAFxIe2o0p9AzrKJlWF2QaO8QmkuHeiDIU9hL7tiCHoUjl9vmnMhAnYnP7Eg6VgNnEUTRE29d64jQT/iBcWTQtNrUzyD6MJ+dkcwRQIhAOEsV5anTkloSmTZRbimMyBKqHoJYXcBBe8lLiPYC7mUAiAz2aNOpfQ/1LycWloIMvdhxzinq5X7Uas/uOSb9wh8d3ASQLVkfpW/GO6wdT6AuuSJ56TtM343pDNH+iSzxltIfdrPiUxT5rf4k21lQQuPClXm9+SfKrCiUXZK7dj0/GWTYQg="}, {"validation_public_key": "ED38B0288EA240B4CDEC18A1A6289EB49007E4EBC0DE944803EB7EF141C5664073", "manifest": "JAAAAAFxIe04sCiOokC0zewYoaYonrSQB+TrwN6USAPrfvFBxWZAc3MhAgOKcvIuchalrZw/glTuOxV3IOCcporxMB7JqAVupk1edkcwRQIhAOvRzpe+IYZK1MyInIQZ87JvP2J8SIXCXZMPBCdITBamAiASavJXi9pws8rDDJSxhGMlmE7zI5bSA8ivtRC9Lgq+UXASQDl3eoqLID+ETJNM+zbMuvwvcHEIxeBZkZ9fp5jJv6OCTPwlj4TJSuy1avEWqUYS2riv5Dvl2haFUoCHf4yawAA="}, {"validation_public_key": "EDEE10DC36ACD995C8E0E86E3CD2FBF8301A4AC2B8847B61A1935DE4973B407C0E", "manifest": "JAAAAAFxIe3uENw2rNmVyODobjzS+/gwGkrCuIR7YaGTXeSXO0B8DnMhAmX0vb7j+lgBjFjbN9RlA86J7AO2Vn6HLquO3aisK4mwdkYwRAIgfxBLn7i4jg/di0U25q6kIbVfTzqbA0SCpQ0I57TOFkcCIFMtJQpENjB2K2EmvBHPvNcwuSPc3vsEeqE2rNJ/cT5DcBJAf68XPFu5RjCeLgpFJM7PKFLgoV8e1nxO5ewjq9Q+TAEGnFyS0IOwf6pOOtIVMdVeXu1v6p4fhXQkdihHt1x6Ag=="}, {"validation_public_key": "ED583ECD06C3B7369980E65C78C440A529300F557ED81256283F7DD5AA3513A334", "manifest": "JAAAAAFxIe1YPs0Gw7c2mYDmXHjEQKUpMA9VftgSVig/fdWqNROjNHMhAyuUnzZZ1n2/GaTmE1m7H/v9YlZyDEwHY3gSHUA3ICL9dkYwRAIgHx2PHvidoN+5yG9WeAS2k7nwIM8ajxQW6wjvt8kBenACIDNxQPQkDyDJH9seS5C62mAarQmgiN89YS3jhNtnvEIqcBJAj7Jh0Kac+aJdpoepu/+eJKnnFQ7YByZB8eMZ+SS1zLhE+lip/49qqVNcpAxEqfaGtxJzoDDD1/QbuU7NOSPkCg=="}, {"validation_public_key": "ED95C5172B2AD7D39434EEBC436B65B3BB7E58D5C1CEFC820B6972ACAD776E286A", "manifest": "JAAAAAFxIe2VxRcrKtfTlDTuvENrZbO7fljVwc78ggtpcqytd24oanMhAiqcRde3MQZ075fa4ZNNyRaYJGMdBNkBnn3bQrKseBDQdkYwRAIgU+LfcE71DPVrO+KtUBjQ9D2u0k/Pr7lukO1nPRj6hSACIDNLYC/JFgobCsIa0BGw+6bUnOw9meU3FdXgR7Q7SoqJcBJAXQakOoQnPp3pcLL7zdKCPUX4b+/FC9Unhqp+O9xQFnRaCWVGmk5MJOIMs4WOQdpM1j3OgSsABmRuCXYvwo/nDw=="}, {"validation_public_key": "ED91EA1E0845DCA1F2E1963BA0D45F30C943DF28F3BFB0A10174365137C7F6E9C4", "manifest": "JAAAAAFxIe2R6h4IRdyh8uGWO6DUXzDJQ98o87+woQF0NlE3x/bpxHMhAy0y9dGPsh3zyCOznqVlLDQ38u4K2G/6wgvJDMUuQg+sdkYwRAIgNEZc1LDaxyIUxrJDP0euBtNjIQnrZjRPOtlVgGymcD0CIAXHIkub5DVkmoKdOPGYPZPNs7qjCTVG/NgL4IhZCcdpcBJAqnAtvvQcyaUf9aW6AsE2szW6hlqDiJ5SBri9i0BAlUVGQCFugQpp1kZJ8MrReR5lU4N0Wfu3W8whCIJ4zYSpCw=="}, {"validation_public_key": "ED30604DA11EBAB73C4A2830F014D6F84BD4B1C260BB1A4E2F9063C1A7B4384A96", "manifest": "JAAAAAFxIe0wYE2hHrq3PEooMPAU1vhL1LHCYLsaTi+QY8GntDhKlnMhA7mC0y8JZUmLThVLWXk1G3yoBhvC2DWpkPQ7nSeZZIaVdkcwRQIhAO8aT3z7GFPNyfICuVKO0axMdm63itv9x04DEA9LIBe7AiA61aG/rh/7V9SriNqqTVnJg7jQ/ZoXSfUZNr4XHcGtIHASQOX/AIJXEeeO0zI+ysNcpMIdX7iFuse+ox09SrfFy8KsYb6e3TA+TVUXNu/OZKRv+VZlwO79+d/RH0pzWZBqegM="}, {"validation_public_key": "ED8252C2F91523126EEF9A21964C7E487A10D6D63D459139700DBC70D9F7BAD542", "manifest": "JAAAAAFxIe2CUsL5FSMSbu+aIZZMfkh6ENbWPUWROXANvHDZ97rVQnMhA41LoGG44d9TZqT0bakr9dpFCqL+fgXCINmAYCeXf4acdkYwRAIgdMgcVlVPIffb1ITBaWjSJ+Asy7P98GO9WDmiBm42epsCIADSZmxluN/NPn7nwKZ6G3xfeF8lH5ecItPWNrWWOuW4cBJAtstv8IUUMnTZdUzjm8YQDAGqooWCik5ttjYmk46qq2TsWRTIL73Kp9VLHbGrEvNdkn5YLBmdwfTwhWmBriQvAw=="}, {"validation_public_key": "ED63CF929BE85B266A66584B3FE2EB97FC248203F0271DC9C833563E60418E7818", "manifest": "JAAAAANxIe1jz5Kb6FsmamZYSz/i65f8JIID8CcdycgzVj5gQY54GHMhA46ynkiiAAEUGZgMrCHUD6h1zWEbxiA91M16I54uxnO/dkYwRAIgEUJiZ2yqot1XrVU6M/claeRAK5Tx0BGTtykon8JIJCkCIF70vgQpeXpV0v2eqPT8DOqcp1N2CxgBkDn/ylsqOBilcBJAFQJx4jfZaD11nw02L74IYzVtyaRNKVCr4kdHNoyLdmWL9xWCCTwVhUf8nh2YfIpJcFnFp0jaSPUQr6Gwltq9AA=="}, {"validation_public_key": "EDC090980ECAAB37CBE52E880236EC57F732B7DBB7C7BB9A3768D3A6E7184A795E", "manifest": "JAAAAAFxIe3AkJgOyqs3y+UuiAI27Ff3Mrfbt8e7mjdo06bnGEp5XnMhAhRmvCZmWZXlwShVE9qXs2AVCvhVuA/WGYkTX/vVGBGwdkYwRAIgGnYpIGufURojN2cTXakAM7Vwa0GR7o3osdVlZShroXQCIH9R/Lx1v9rdb4YY2n5nrxdnhSSof3U6V/wIHJmeao5ucBJA9D1iAMo7YFCpb245N3Czc0L1R2Xac0YwQ6XdGT+cZ7yw2n8JbdC3hH8Xu9OUqc867Ee6JmlXtyDHzBdY/hdJCQ=="}, {"validation_public_key": "EDC1897CE83B6DCF58858574EC9FE027D4B1538A0F20823800A5529E121E87A93B", "manifest": "JAAAAAFxIe3BiXzoO23PWIWFdOyf4CfUsVOKDyCCOAClUp4SHoepO3MhAyzghN7DPPb6DQk+C8jD6VxnAtvrMP3wb4dUWvikOyb6dkcwRQIhANmpvnJnNABmsVVTgZGG9/gJ2gO10+reIvj1RmCN27kuAiBqG5TMjHKdSHDo2kRX/yIc6ZbzMxCeQNg0p/VQYHB70HASQEEWeQ3EJKifr/rFQRGYTATKtK/KmSyR246DAYGDkMwmqZ9MUhjAalWPdSks+q8E8lmxnkElmJ9IRL80efslCAQ="}, {"validation_public_key": "ED5E82276BCC278499E4285399789F5A93196166B552957997A61599D4F8613959", "manifest": "JAAAAAFxIe1egidrzCeEmeQoU5l4n1qTGWFmtVKVeZemFZnU+GE5WXMhAw2OjN7E3AfWx4sAN7k+8SdHypV6PKv/LdnCt1OiCf+RdkYwRAIgf5hIqlhCsDXUmJqdrU6CaM+tl34yqRo7QzOYB2JEyo8CIFfMBva7js/PM9yyJo95jxE+VTpWCxXd9o7c7qjyituTcBJA+biCZchkbricoQKMSbtUFRih10Khob4lva+SMz6ldA8c5wXWUnOlqZ7WWyG1y+FaM7CzDAx4iEg3KMQm44nUCQ=="}, {"validation_public_key": "EDF10074F5FBBB975A8EA8E9C42306854E6A49C71B7D33B0293AB1830FECF2C400", "manifest": "JAAAAAFxIe3xAHT1+7uXWo6o6cQjBoVOaknHG30zsCk6sYMP7PLEAHMhA/50gU8eWLqwVPKzk0Nj5bAc+xJ1mFevzP4eN7GIFs53dkcwRQIhANeYigL33Z1iQ4yq++CaiSy3AHLwE9yuSJ+2z84s9ypJAiBZPg/KKOXZpusZwXhrHvwOzWDSeDJ0W/V1iEQnMhw+vHASQLW0r5r+nG+x+F5b3Y8aAJQhkX1CBOhgFFeuAmCvUO2f6vlEx455hDtJqI8N84a0Kg5Y+gmzpsESNFXEJBH1xwE="}, {"validation_public_key": "EDFE65FB385B6BB16951153D2A0F32BD6D8CC4532C87BB3E1900913A7BE34F5EF7", "manifest": "JAAAAAFxIe3+Zfs4W2uxaVEVPSoPMr1tjMRTLIe7PhkAkTp7409e93MhA31gXDB4wVF06XPQM3fScxfWHkoRE5kggC/SEwXCYSHDdkcwRQIhAMSEv7ka1d70zTe3ctwBb9d+hx+wZjveZbcVuphfzRg/AiBOjyeTN0fvbjmur+lV/ovG1A9Zfkn7HmO7nbrFiorLwXASQLAHLgKpleHyaSQv0O4dCI0rSuvPR4Svw9FkMCorVZKG7ywAmKN2hRW8UraUfqm2HpQCq4AASgRoR2/YhBQCEgo="}, {"validation_public_key": "ED58F6770DB5DD77E59D28CB650EC3816E2FC95021BB56E720C9A12DA79C58A3AB", "manifest": "JAAAAAFxIe1Y9ncNtd135Z0oy2UOw4FuL8lQIbtW5yDJoS2nnFijq3MhA+QZVFEvfIH4IlclPsVfTcaKgR3XNrXNk97GxtKYBR3jdkcwRQIhAOgnllsWVvhWHfvVOsdXGsQjrRZp2buWISeq6GSYiz7FAiAcCO8OmHivZjwAl+dN1J/9FJ+cElxcpr/M+CaHkUBt6HASQDTO+yf+h1naBQgQmY32ajTvpPLsp4gQUxaYlTl0vdkeXHyAntECezgoxWBlo9IrEzBFzWOfXFTx4bwTrEMuBAk="}, {"validation_public_key": "ED5784A43AA84B5BDAFD0AFEF64ADA5583A3129182C6A7464950FD6BF2D9FAE5B0", "manifest": "JAAAAAFxIe1XhKQ6qEtb2v0K/vZK2lWDoxKRgsanRklQ/Wvy2frlsHMhArdbSEl/Oha4I5VI0qVxmc1zBWoRb5YnutciOC0l+OYddkcwRQIhAIqluIgtzGJZJG9s7t2558ipnGfgXOZxOBN+VXey4iSmAiAWJzzanXjXImMB/VtHHrqs1V4xnlg8uF+y7Ms+1vMGZnASQCZYnNR3aSlwdYpRkP5v1V9a5BesJUZD6UJ1nMr5b5VoOml+DjVtDUZysrCIx00a+gLz+th86gTey7UnCrqgQgk="}, {"validation_public_key": "ED75940EC09130F9C553D8AF0FE354A112CC27251472AF1A90917597489192135F", "manifest": "JAAAAAFxIe11lA7AkTD5xVPYrw/jVKESzCclFHKvGpCRdZdIkZITX3MhAozHf//RpGgNExPNP8S2HDLH5NQErqjPSZy99Kn8G31mdkcwRQIhAKJW0DjI1xeTYBlDE9qY9t32suLV3hsQo0SW4cvGm0DcAiA7AKg7SSHAVnJnG7HkJU6jxTj9qPRg6/o6lAxyWFRsenASQPP5nJBFTluxZ1CJ+MlHAQXOn4HjReHkNfD0JF2EFkKXRcd/1HrnE9uGPt31EWWhPU1+s6tsbIx7wy9mq5XcHQ0="}, {"validation_public_key": "EDF4CC5AB784DC569D9BBD46982B1CF80A79BB4C0AD1CA1270F1D8B5EA4A5B950B", "manifest": "JAAAAAFxIe30zFq3hNxWnZu9RpgrHPgKebtMCtHKEnDx2LXqSluVC3MhAoH3kciMcuyYxaV7xox0PG/DKuzF1T7u/RmUtGkBf0UNdkcwRQIhALnQ0rBlGS/PrNNVKjkhyJnQqzelRztgA4kC0xewQhXoAiBYvLfFq14UNYVy8ffGec0VRcTm7ZZR1qx+jDo4CFPyyHASQDW7A9Nulxybe/IK5QhXBp71uGi7FQ2RCww/WvK4kVidmxlTh+MjHIOid8VxNmATmDfpgXMi8R8ZC6TSVEA3ygI="}, {"validation_public_key": "EDCFE65121E39A2955F04D6D784E3B021791E88D1393DA4AFAB89F99A929A72924", "manifest": "JAAAAAFxIe3P5lEh45opVfBNbXhOOwIXkeiNE5PaSvq4n5mpKacpJHMhAltq4c6NJj0hvl47bShHCNZCda5jKSb5Q8UKoHagJKVndkYwRAIgKNsTb54BtOL/nKTuLqFJ2RQTLV1QuVJpBCjmCgiW0csCIC/49bK6J420PF3lLRULAiJctYGAIavqxLSsHDki+KvfcBJAkcOaWwuQ0DpyV/zjBfcdjLYC5YbMy0NKGn+8Iy1gLcXUkYtU40hW78wcJzYPZPSfSP+JBVTVsCXRs8wrdqsWAw=="}, {"validation_public_key": "EDA5AAE0DB134B809F8D664888F7EC4FCE98DC4D00B33301032424941C16C2F0F7", "manifest": "JAAAAANxIe2lquDbE0uAn41mSIj37E/OmNxNALMzAQMkJJQcFsLw93MhAgbEaxgObrbcqWdV+e73GPAXIShqbsqfKHM9Yzvke3DUdkcwRQIhANcZkOl7HGXO1vp9Zbu0AecBgsfTjVEMn0ADiIxGrsisAiAsyvbeMaiUoaflFDJPVZQjZ0eV3eVGlzjQHhg9vJv4MXASQD+zcPFXd+7umjy/G6BNRDHEUmC5Cq2ypAYbMxTszDB948dj93OoLSNXBUAov2lndDzuyJCXXtXAF0Q8Fj/6sQI="}, {"validation_public_key": "ED760E58A14E57C91F74C6864E279C0000F3ED2D868BA6812197DF1348D3F7A4D7", "manifest": "JAAAAAJxIe12DlihTlfJH3TGhk4nnAAA8+0thoumgSGX3xNI0/ek13MhApXxQyFRip+9NdEt7qedWZfLF6vOmBoYR/Xar232RP3rdkcwRQIhAMBhxraztWb7erMijAarunSRk/pJqr/d0Cumg+OYuT3+AiAUxqvumErWO0n+KSY6PA6o9n5nBk5z33E1AQdBlpd7FXASQDK4ooXG4fhGxLB7i9h43dnzUid29+3kD/vTUir3T0cjC2+FLLzZj8A085gC1EBicfLjduvjxhCV1RpM3eJVGQE="}, {"validation_public_key": "EDC2A138B3771C208965596D4D372331C17A5476BD2CE2BC7A6D3CD273DF330D99", "manifest": "JAAAAAFxIe3CoTizdxwgiWVZbU03IzHBelR2vSzivHptPNJz3zMNmXMhA9j/pUGrPDYl63JdWVsqbHWDBdJ9H57NVL42LO6gLwo1dkcwRQIhAJeTyxdK1KYpxxI8kLvhzCz5OhGZ42lFCYMSwMmavI4pAiBsWsvxet4JBhZun9ZoZJpCZ/VuNIt10YlnrtcNcEBe53ASQHDJJeC4NJZlvm1WI5y/byOh4hvY8fqsmD0bXZsSN9G3TRALSLeCkdLRGbJZNMODXflcp+tHfU7FX4JOdRVMxQ0="}, {"validation_public_key": "EDA4074FD039407BD2464F14C378440D5B02CA8FBA661B286D1C82A3D59E8E6EC0", "manifest": "JAAAAAFxIe2kB0/QOUB70kZPFMN4RA1bAsqPumYbKG0cgqPVno5uwHMhAyOoxmjn+Zp/8TcU2P+qJAEKRmgg2ziW8eP/BshOzM5cdkcwRQIhAJxbW/beoMl811igSI+5P3B4Fnd9wVYc9sd0XbKhImFoAiBmTH7knrw3xWifMFClZm09BL0TYul2c+5o8Zp43MExR3ASQNmCwIgkMoqa7iqqI39XTMLFWlrqSQWsMdHcqvxZuVMU+YB2cSsAFkepe/RiskfPC3yJsc2k4US5nCQyqXdZ5QQ="}], "sequence": 10, "expiration": 697075200}
Verified:  True
```

## Contributors
* Antonios Inglezakis (@antiggl), Leading Researcher and Developer, University of Nicosia
* Alloy Networks (@alloyxrp)

## Acknowledgements
This work is funded by the Ripple’s Impact Fund, an advised fund of Silicon Valley Community Foundation (Grant id: 2018–188546).
Link: [https://ubri.ripple.com/]

