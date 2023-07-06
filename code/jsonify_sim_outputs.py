#!/usr/bin/env python3
# -*- coding: utf-8 -*-
##################################################

#sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/secure-domain-validation/map-reduce")
#sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/sdv2/map-reduce")

import utils.map_reduce
import argparse
from datetime import datetime
import json
import os
import numpy as np
import sys
import toolz
import traceback

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output_dir",
                        help='Directory of simulation outputs')
    parser.add_argument("-a", "--aslist",
                        help='File containing list of attacker ASes')
    parser.add_argument("-f", "--output_file",
                        default="pattern-str-dict.json",
                        help='Output file')
    return parser.parse_args()


def reduceFunction(resObject1, resObject2):
    for vp in resObject2:
        if vp in resObject1:
            vpObject2 = resObject2[vp]
            vpObject1 = resObject1[vp]
            for ocid in vpObject2:
                if ocid in vpObject1:
                    ocidObject2 = vpObject2[ocid]
                    vpObject1[ocid] |= ocidObject2
                else:
                    vpObject1[ocid] = vpObject2[ocid]
        else:
            resObject1[vp] = resObject2[vp]
    return resObject1


def mapFunction(fileAdversaryIndexDictVersionTuple):
    fullVPList = ["gcp_asia_northeast1", "gcp_asia_southeast1", "gcp_europe_west1", "gcp_europe_west2", "gcp_europe_west3", "gcp_northamerica_northeast2", "gcp_us_east4", "gcp_us_west1", "ec2_ap_northeast_1", "ec2_ap_south_1", "ec2_ap_southeast_1", "ec2_eu_central_1", "ec2_eu_north_1", "ec2_eu_west_3", "ec2_sa_east_1", "ec2_us_east_2", "ec2_us_west_2", "azure_japan_east_tokyo", "azure_us_east_2", "azure_west_europe", "azure_germany_west_central", "le_via_west"]
    vpsUnassigned = set()
    resilienceObjectDict = {}
    file = fileAdversaryIndexDictVersionTuple[0]
    adversaryToIndexDict = fileAdversaryIndexDictVersionTuple[1]
    adversaryCount = len(adversaryToIndexDict)
    version = fileAdversaryIndexDictVersionTuple[2]
    print("[{}] Starting mapping on file {}".format(str(datetime.now()), file))
    try:
        for line in open(file):
            sline = line.strip()
            if sline == "":
                continue
            splitLine = sline.split(";")
            ocid = splitLine[0]
            originStatement = splitLine[1]
            originStatementSplit = originStatement.split(",")
            lastOriginData = originStatementSplit[-1]
            adversary = lastOriginData.split(":")[0]
            pathStatement = splitLine[2] #",".join(splitLine[2:])
            if pathStatement == "":
                adversaryWon = False
                for vp in fullVPList:
                    if vp not in resilienceObjectDict:
                        resilienceObjectDict[vp] = {}
                    if ocid not in resilienceObjectDict[vp]:
                        resilienceObjectDict[vp][ocid] = np.zeros(shape=(adversaryCount,), dtype=np.uint8, )
                    adversaryIndex = adversaryToIndexDict[adversary]
                    resilienceObjectDict[vp][ocid][adversaryIndex] = 3 if adversaryWon else 2 
            else:
                splitPathStatement = pathStatement.split("|")
                unusedVPs = set(fullVPList)
                for vpStatement in splitPathStatement:
                    splitVPStatement = vpStatement.split(", ")
                    asPath = splitVPStatement[2][1:-2].split(" ")
                    vp = asPath[0]
                    adversaryWon = False
                    if asPath[-1] == adversary:
                        adversaryWon = True
                    if vp not in resilienceObjectDict:
                        resilienceObjectDict[vp] = {}
                    if ocid not in resilienceObjectDict[vp]:
                        resilienceObjectDict[vp][ocid] = np.zeros(shape=(adversaryCount,), dtype=np.uint8, )
                    adversaryIndex = adversaryToIndexDict[adversary]
                    resilienceObjectDict[vp][ocid][adversaryIndex] = 3 if adversaryWon else 2 
                    # 3 is adversary won because it has the low order bit set. 
                    # 2 is adversary did not win because it can be bitmasked with not 2 to easily be removed and create an array of 0s and 1s.
                    unusedVPs.remove(vp) 
                    # This line will error if the full vp list does not include VPs that were used in the simulation.
                for vp in unusedVPs: 
                    # Iterate through any VP we didn't see in this simulation result (because of connectivity issues) and assume the adversary did not win because these VPs did not have connectivity to the adversary.
                    adversaryWon = False
                    if vp not in resilienceObjectDict:
                        resilienceObjectDict[vp] = {}
                    if ocid not in resilienceObjectDict[vp]:
                        resilienceObjectDict[vp][ocid] = np.zeros(shape=(adversaryCount,), dtype=np.uint8, )
                    adversaryIndex = adversaryToIndexDict[adversary]
                    resilienceObjectDict[vp][ocid][adversaryIndex] = 3 if adversaryWon else 2 

        print("[{}] Done mapping file {}".format(str(datetime.now()), file))
    except:
        e = sys.exc_info()[0]
        traceback.print_exc()
        print("Error on file {}. Error info: {}.".format(file, repr(e),))
    return resilienceObjectDict


sumUnperformedSimulations = 0
sumTotalSimulations = 0
def ndArrayToPatternString(ndArray):
    global adversaryCountGobal, bitMaskGlobal, bitOrGlobal, sumUnperformedSimulations, sumTotalSimulations
    sumTotalSimulations += adversaryCountGobal
    sumUnperformedSimulations += adversaryCountGobal - np.count_nonzero(ndArray)
    # Assumes an ndarray with int8 types where 3 is adversary won and 2 is adversary lost.
    return ((ndArray & bitMaskGlobal) | bitOrGlobal).tobytes().decode('ascii')


adversaryCountGobal = 0
bitMaskGlobal = None
bitOrGlobal = None
def main(args):
    global adversaryCountGobal, bitMaskGlobal, bitOrGlobal, sumUnperformedSimulations, sumTotalSimulations
    
    # This needs to be an adversary to index dictionary instead.
    adversaryToIndexDict = {}
    index = 0
    for line in open(args.aslist):
        sline = line.strip()
        if sline == "":
            continue
        adversaryToIndexDict[sline] = index
        index += 1
    adversaryCountGobal = len(adversaryToIndexDict)
    bitMaskGlobal = np.full((adversaryCountGobal,), 0x1, dtype=np.uint8)
    bitOrGlobal = np.full((adversaryCountGobal,), 0x30, dtype=np.uint8)
    patternStringDictNumpy = map_reduce.singleNodeWithReductionBetweenRounds([(args.output_dir + "/" + f, adversaryToIndexDict, 3) for f in os.listdir(args.output_dir)], 38, mapFunction, reduceFunction, {})
    print("Map reduce finished. Converting numpy dict into JSON serializable string dict.")
    json.dump(toolz.valmap(lambda ocidDict: toolz.valmap(ndArrayToPatternString, ocidDict), patternStringDictNumpy),
        open(args.output_file, "w")) # Use 40 for shadow-data runs. 16 for personal laptop runs.
    print(f"Total simulation results recorded: {sumTotalSimulations}, Missing simulations: {sumUnperformedSimulations}")


if __name__ == '__main__':
    main(parse_args())
