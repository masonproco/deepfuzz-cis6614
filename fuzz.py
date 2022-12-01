#importing random module
import random
import math
import qrcode
import os

# Import custom modules
import enumerate_utils
import generator
from logger import FuzzLogger


#stores random character to be used for fuzzing
characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \"\'!#$%&'()*+,-./:;<=>?@[\\\]^_`{|}~"
i = 0
j = 0
k = 0
specific = ""
randomrange = 0
selectfuzz = 0
data =""

iterations = 100
depth = 1
timer = 0

log = FuzzLogger.initializeLogging()
crash_dict = {}

# Fuzz the function
def fuzzFunction(functions):

    count = 0
    traverse = True

    for function in functions:
        i = 0
        function_name =     function[0]
        function_address =  function[2]

        print("Fuzzing function " + str(function_name))

        # Generate random input and fuzz
        while count < iterations:

            param_names = enumerate_utils.getFunctionParamName(function_address)
            inputs = handleInputGeneration(param_names)
            
            res = []

            try:
                res = function_address(**inputs)
            except Exception as err:

                if function_name in crash_dict:
                    if crash_dict[function_name] == repr(err):
                        count += 1
                        continue
                
                if "AttributeError" in repr(err):
                    count += 1
                    continue

                error_state = {
                    "Function Name" : function_name,
                    "Input"         : inputs,
                    "Error Message" : repr(err)
                }

                print("ERROR DETECTED")
                print("Logging error " + repr(err) + " for function " + str(function_name))

                crash_dict[function_name] = repr(err)
                log.info(repr(error_state))

            if traverse:
                # print(res)
                children = enumerate_utils.checkChildObject(res)

                if children != []:
                    enumerate_utils.enumerateChildFunctions(qrcode, children, res, depth)
                
                traverse = False

            count += 1

def handleInputGeneration(param_names):
    inputs = {}
    i = 0
    for i in range(0, len(param_names)):

        if param_names[i] == "kwargs":
            i += 1
            continue

        if param_names[i] == "self":
            inputs[param_names[i]] = ""
            i += 1
            continue

        inputs[param_names[i]] = generator.generateRandomBytes()
        i += 1

    return inputs

def main():

    functions = enumerate_utils.enumerateLibraryFunctions(qrcode)
    functions_and_param_count = enumerate_utils.enumerateFunctionArgs(functions)

    fuzzFunction(functions_and_param_count)

    # print("Enter the minimum number of characters for inputs...")
    # min = int(input())
    # print("Enter the maximum number of characters for inputs...")
    # max = int(input())
    # print("Does fuzzing target require specific characters? Y/N")
    # specific = input()
    # if specific == "Y" or specific == "y" or specific == "yes" or specific == "Yes":
    #     print ("Indicate where in the string characters are required\nEnter a '*' for characters that are to be randomized")
    #     print ("Enter other characters to format the string\nExample for date format: **/**/****")
    #     data = input()
    # while selectfuzz !=1 and selectfuzz !=2 and selectfuzz !=3:
    #     print("Enter a number to indicate type of fuzzing\n1 = Numeric fuzzing with integers")
    #     print("2 = Alphanumeric fuzzing output as a string\n3 = Alpanumeric fuzzing with special characters, output as a string")
    #     selectfuzz = int(input())
    #     if selectfuzz !=1 and selectfuzz !=2 and selectfuzz !=3:
    #         print("Please enter 1, 2 or 3")
    
    #calls fuzz functions based on inputs
    # if selectfuzz == 1:
    #     numf()
    # if selectfuzz == 2:
    #     alphanum()
    # if selectfuzz == 3:
    #     alphanumspec()    

if __name__ == "__main__":
    main()
    
