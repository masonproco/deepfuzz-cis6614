import random
import os

def generateRandomBytes():
    length = random.randint(0, 4080)
    rand_bytes = os.urandom(length)

    if addNullByte():
        index = random.randint(0, len(rand_bytes) - 1)
        byte_list = bytearray(rand_bytes)
        byte_list[index] = 0x00
        rand_bytes = bytes(byte_list)

    return rand_bytes

def addNullByte():
    probability = 1
    chance = random.randint(0, 100)

    if chance == probability:
        return True
    else:
        return False