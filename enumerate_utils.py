import inspect
import fuzz

# Get functions from a library
def enumerateLibraryFunctions(lib):
    return inspect.getmembers(lib, inspect.isfunction)

# Get the number of args for a function
def enumerateFunctionArgs(functions):

    function_args_address = []

    for function in functions:
        args = inspect.signature(function[1])
        parameter_count = len(args.parameters) - 1
        function_args_address.append((function[0], parameter_count, function[1]))
       
    return function_args_address

def getFunctionParamName(function):
    args = inspect.signature(function).parameters
    return parseOrderedDict(args)


def parseOrderedDict(signatureParams):
    param_names = []
    for param in signatureParams:
        param_names.append(param)

    return param_names

# Check if child object has methods attached to it
def checkChildObject(childObject):
    # print(childObject)
    if childObject == []:
        return []

    return dir(childObject)

def isPrivate(function):
    if function[0] == "_" and function[1] == "_":
        return True

    if function[0] == "_":
        return True

    return False

def enumerateChildFunctions(lib, functions, childObject, depth):
    i = 0

    # for i in range(0, depth):

    for function in functions:

        function_args_address = []
        
        if isPrivate(function):
            continue
        
        if function in vars(childObject):
            continue

        child_function = getattr(childObject.__class__, function)

        if callable(child_function):
            # print(child_function)

            args = inspect.signature(child_function)
        
            parameter_count = 0
            for param in args.parameters:
                if param == "self" or param == "kwargs":
                    continue
                parameter_count += 1

            function_args_address.append((function, parameter_count, child_function))
            fuzz.fuzzFunction(function_args_address)

            # print(args)
    # print(args)
    # parameter_count = len(args.parameters) - 1
    # print(getattr(function))
    # function_args_address.append((function, parameters_count, getattr(function)))