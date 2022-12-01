import logging
import os


class FuzzLogger():
        
    def initializeCrashDirectory():
        if os.path.exists("./crashes"):
            return
        else:
            os.mkdir("./crashes")
    
    def initializeLogging():

        FuzzLogger.initializeCrashDirectory()

        logging.basicConfig(filename='./crashes/crashes.txt',
                        filemode='a',
                        format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                        datefmt='%H:%M:%S',
                        level=logging.DEBUG)

        logging.info("Initializing logger...")
        return logging.getLogger('FuzzLog')
        