# topology-simulator
Topology simulations based on modeling on quicksand.

# Usenix 23 Artifact Evaluation
At a high level, the simulation code can be evaluated by running ```code/simulate.py``` with the specified input files in ```data/```. After the simulation result for the RPKI and non-RPKI simulations can be combined with DNS data to compute resilience of domain names using code in the ```princeton-letsencrypt``` repo (more description in parent repo). Below is a description/interpretation of the input and output formats, a description of how the input files were generated, and commands to rerun the simulations given a scaled-down version of the input files.

## An overview of simulate.py
simulate.py performs an interdomain Internet topology simulation based on the "routing tree" algorithm discussed in "Modeling on quicksand: dealing with the scarcity of ground truth in interdomain routing data" (https://dl.acm.org/doi/10.1145/2096149.2096155). Running ```python3 simulate.py -h``` (from the code directory; all python commands are intended to be executed from the code directory) gives the help output showing the various input file flags:

```
usage: simulate.py [-h] [-t TOPOLOGY_FILE] [-o ORIGINS_FILE] [-p POLICIES_FILE] [-b TIE_BREAKER] [-O OUTPUT_FILE] [-e]

optional arguments:
  -h, --help            show this help message and exit
  -t TOPOLOGY_FILE, --topology_file TOPOLOGY_FILE
  -o ORIGINS_FILE, --origins_file ORIGINS_FILE
  -p POLICIES_FILE, --policies_file POLICIES_FILE
  -b TIE_BREAKER, --tie_breaker TIE_BREAKER
  -O OUTPUT_FILE, --output_file OUTPUT_FILE
```

This flags specify all input files to the simulation framework. Below they are explained in order.

### TOPOLOGY_FILE
This is a CAIDA AS-relationship dataset topology file. It contains an AS-level Internet topology graph inferred from public BGP data. These are publicly available and are released monthly by CAIDA based on RIB files from public route collectors. The topology file from 2022-03-01 is included in the ```data/topo``` directory for convenience, but other files can be downloaded at https://www.caida.org/catalog/datasets/as-relationships/.

### ORIGINS_FILE
Given the Internet topology, the simulator must simulate BGP announcements over the topology. The origins file specifies which ASes should announce a prefix that is simulated in each topology simulation. Every line of the origins file corresponds to a distinct simulation. The origins file format is:

```
<prefix_name>:<comma separated list of origin ASes>
```

For example, the first line of the origins file ```data/origins/origin-segments/origins-seg-001.txt``` is 

```
1000:209102,138245
```

which causes the simulator to run a simulation for an arbitrary prefix indexed by the key ```1000``` that is originated by the ASes 209102 and 138245. This will trigger a full Internet routing simulation for this prefix presuming it is announced by these ASes. The simulator will find the AS-level route used by every AS in the CAIDA topology and determine which of the four origin ASes that route will send its traffic to. In this setup, AS 209102 is a victim AS and AS 138245 is a randomly chosen AS on the Internet that is serving as an adversary in this simulation. By convention, we use the last AS in the origin line to signify the adversary being simulated. The script that process the simulation output make this assumption, but the simulator does not treat the adversary differently than the legitimate origins in the simulations.

The origins files are not stored in the Github repo due to size constraints. The origin files are stored in tar format in an S3 bucket: to downloaded and extract the files in the `data` directory, run the following commands:
```
cd data
wget https://usenix23-artifact-data.s3.us-west-2.amazonaws.com/simul/origin-segments.tar.gz
tar -xzvf origin-segments.tar.gz
```.

Valid origins files are in the ```data/origins/origin-segments``` directory. ```data/origins/origin-segments``` contains a 10% subset of the random sample of 1000 ASes used in the paper. This is a rather large simulation. Based the speed of the simulation on a benchmark we performed on a personal computer, this file will take about 60 hours to run.

### POLICIES_FILE

In addition to running a conventional routing simulation, the simulator has the option of loading a policy file that can augment the routing behavior of select ASes on the Internet. A large number of scenarios can be encoded into the policies file, but we specifically used it for two functions: 1) adding the routing policies for cloud provider hosted-vantage points to the CAIDA topology (cloud providers typically operate all geographic locations from a single AS number, which are not well resented in the CAIDA topology given that it often omits peering relationships that do not appear in public data sources) and 2) optionally instructing adversary ASes to prepend their announcements as is required to evade ROV enforcement (in ```policies-all-prefixes.txt```). The policies file also contain data about the announcement patterns of real prefixes seen in BGP RIBs.

We include both the standard non-ROV and ROV versions of the policies file in ```data/policies/policies-all-prefixes.txt``` and ```data/policies/policies-all-prefixes.txt``` respectively. Changing between these two versions of the policies file can determine whether the standard or ROV version of the simulations are being run.

### TIE_BREAKER
This changes the tie break behavior of the simulation when all Gao-Rexford conditions tie. The default tie break was used in the paper to this flag does not need to be set.

### OUTPUT_FILE
This is the location to write the output of the simulation. The simulation produces two output streams: a full debug stream to stdout and a concise output file specifically formatted for these analysis tasks that is written to OUTPUT_FILE. The format of OUTPUT_FILE is:

```
<prefix>;<origin>:<number of ASes in the Internet topology that route data to that origin>,...;[path from remote vp to prefix]|...
```

(Note that the ordering of lines within the script's output may differ from run to run, as the script uses multiple threads to process simulations and write output in parallel.)

For one example, the first line of output in ```sim-outputs/nonrpki/out-001.txt``` is


```1000;209102:25640,9321:47824;[1, 2, "gcp_asia_northeast1 60501 209102"]|[1, 2, "gcp_asia_southeast1 60501 209102"]|[1, 1, "gcp_europe_west1 209102"]|[1, 1, "gcp_europe_west2 209102"]|[1, 1, "gcp_europe_west3 209102"]|[1, 1, "gcp_northamerica_northeast2 209102"]|[1, 2, "gcp_us_east4 60501 209102"]|[1, 1, "gcp_us_west1 209102"]|[1, 2, "ec2_ap_northeast_1 60501 209102"]|[1, 2, "ec2_ap_south_1 60501 209102"]|[1, 2, "ec2_ap_southeast_1 60501 209102"]|[1, 2, "ec2_eu_central_1 60501 209102"]|[1, 2, "ec2_eu_north_1 60501 209102"]|[1, 2, "ec2_eu_west_3 60501 209102"]|[1, 2, "ec2_sa_east_1 60501 209102"]|[1, 2, "ec2_us_east_2 60501 209102"]|[1, 2, "ec2_us_west_2 60501 209102"]|[1, 2, "azure_japan_east_tokyo 60501 209102"]|[1, 2, "azure_us_east_2 60501 209102"]|[1, 2, "azure_west_europe 60501 209102"]|[1, 2, "azure_germany_west_central 60501 209102"]|[2, 3, "le_via_west 3356 4766 9321"]```

This line can be read as the 25640 ASes on the Internet routed data for prefix 1000 to AS 209102 in this simulation, while 47824 ASes routed to the attacker AS 9321. The final part of the line provides information about the routing selections at various cloud vantage points modeled in the simulation, which is vital for the resilience of different multiVA deployment configurations. In this simulation, all vantage points except le_via_west routed traffic for prefix 1000 to the true origin AS 25640, hinting to multiVA's strength at detecting an attack that Let's Encrypt's primary vantage point would have "believed."

## Running simulate.py

simulate.py primarily depends on python3. We were able to run it on a clean Ubuntu 22.04 VM with no ```apt``` or ```pip``` commands as it only depends on already-installed standard libraries.

Before running the simulator, we recommend you make a directory called ```output/``` in the repo that will be ignored by git (based on the repos ```.gitignore```). From the base of the repo run:

```mkdir output```

Then cd to the code dir:

```cd code```

Below is an example run command that can be executed from the ```code/``` directory that points to all the default input files contained in the data directory and generates two output files in the ```output``` directory: one is a file with the concise simulation output (```../output/simul800-output.txt```) and the other is the full simulation debug output (```../output/simul800-status-output.txt```). This command also sends the status output to stdout for convenience. (note the -u flag on the python command that allows for status output during the execution of the simulation by avoiding buffering)

```python3 simulate.py -t ../data/topo/20230301.as-rel2.txt -o ../data/origins/origin-segments/origins-seg-000.txt -p ../data/policies/policies-all-prefixes.txt -O ../output/out-000.txt ```

This simulation took us 26 minutes on a personal machine with a recent generation CPU. This version of the script is not multi-threaded so it will not benefit from being run on a cluster/HPC node. Once the above simulation command runs, it will generate the standard non-RPKI output files.

Below is a variant of the command that loads the RPKI policies file to run the RPKI simulations and writes the RPKI/ROV output files:

```python3 simulate.py -t ../data/topo/20230301.as-rel2.txt -o ../data/origins/origin-segments/origins-seg-000.txt -p ../data/policies/policies-all-prefixes-rpki.txt -O ../output/out-000.txt ```

Post-processing requires both the standard and RPKI results to apply scenarios of universal RPKI adoption, real-world RPKI-ROA adoption today, and no RPKI usage. The RPKI results should run at a comparable speed to the standard simulations.
