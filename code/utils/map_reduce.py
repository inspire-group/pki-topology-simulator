#!/usr/bin/env python3
# -*- coding: utf-8 -*-
##################################################

#from threading import Thread
#from queue import Queue
from multiprocessing import Pool
from multiprocessing import Queue

from functools import partial
import sys


def superMap(files, initialVal, mapFunction, reduceFunction):
    res = initialVal
    fileCount = 0
    for file in files:
        res = reduceFunction(res, mapFunction(file))
        fileCount += 1
        print("Done mapping and reducing {} of {} files.".format(fileCount, len(files)))
    return res

# This should really be rewritten with processes and a shared job queue instaed of a mapping pool.
def singleNodeLowRam(files, concurrencyCount, mapFunction, reduceFunction, initialVal):
    #output = Queue()
    superMapListLength = int(float(len(files)) / concurrencyCount) + 1
    superFileList = []
    superFileSubList = []
    for file in files:
        if len(superFileSubList) == superMapListLength:
            superFileList.append(superFileSubList)
            superFileSubList = []
        superFileSubList.append(file)
    superFileList.append(superFileSubList)
    print("Superlist generated. Length: {}".format(len(superFileList)))


    with Pool(concurrencyCount) as p:
        reduceList = p.map(partial(superMap, initialVal=initialVal, mapFunction=mapFunction, reduceFunction=reduceFunction), superFileList)
    res = initialVal
    c = 0
    for val in reduceList:
        c += 1
        print("Final reducing {} of {} tasks.".format(c, len(superFileList)))
        res = reduceFunction(res, val)
    print("Finished final reduction. Returning result.")
    return res

def singleNode(files, concurrencyCount, mapFunction, reduceFunction, initialVal):
    with Pool(concurrencyCount) as p:
        reduceList = p.map(mapFunction, files)
    res = initialVal
    c = 0
    for val in reduceList:
        c += 1
        print("Final reducing {} of {} tasks.".format(c, len(reduceList)))
        res = reduceFunction(res, val)
    print("Finished final reduction. Returning result.")
    return res

def singleNodeWithReductionBetweenRounds(files, concurrencyCount, mapFunction, reduceFunction, initialVal):
    filesGroupedByConcurrencyCount = [files[x:min(x+concurrencyCount, len(files))] for x in range(0, len(files), concurrencyCount)]
    #print("File group summary")
    #print(filesGroupedByConcurrencyCount)
    res = initialVal
    for fileGroup in filesGroupedByConcurrencyCount:
        with Pool(concurrencyCount) as p: # Note that this initiates new pools very often (for every file group) and may be slower for crazy high file counts.
            reduceList = p.map(mapFunction, fileGroup)
        c = 0
        for val in reduceList:
            c += 1
            print("Early reducing {} of {} tasks.".format(c, len(reduceList)))
            res = reduceFunction(res, val)
    print("Finished reduction. Returning result.")
    return res

