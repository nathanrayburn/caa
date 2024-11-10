from base64 import b64encode, b64decode

from sage.all_cmdline import *   # import sage library

def bytesToInt(message):
    return int.from_bytes(message, "big")


def intToBytes(i):
    return int(i).to_bytes(16, "big")


# read file
c0_data = open("m0", "rb+").read()
c1_data = open("m1", "rb+").read()
c2_data = open("m2", "rb+").read()

c0 = b64decode(c0_data)
c1 = b64decode(c1_data)
c2 = b64decode(c2_data)

# parse bytes
c0_blocks = [c0[i:i + 16] for i in range(0, len(c0), 16)]
c1_blocks = [c1[i:i + 16] for i in range(0, len(c1), 16)]
c2_blocks = [c2[i:i + 16] for i in range(0, len(c2), 16)]





def crack_message(c0, c1, c2, n0, n1, n2, pub_key):
    # use sage to conv to int
    crt = c0*c1*c2
    crt_N = n0*n1*n2
    plaintext = pow(crt,-pub_key,crt_N)
    print(plaintext)

pub_key = b64decode("MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAvtCUgebFQ43qMwaIZZ+w3aO5NJJLhtUi8THUGk/dScoGY0a6cW0rKuawqmVeoccvx4ZyUy4htOpeJoqjIbijHF/6saD36DvDeJKZlynZujIkZSN/ywCsaDsWypqkDIRJaFfGAY2Px8WPOX0GVui2yFVT+aFPYZZf7OC4Xu7pm4Eov4tM/+Jb54pLJplEMgE41F9KFshBkqtYlfxkpPJ5aocjS0jEby34cZ8o79rQIhGGUuPSXkTaPlH8EzROHDq9deQMYklJspN1urNuH/mmkt856tyhefJrRBfNXXEgH33u970FMzlBV+uc0pJgLEgUSMPCCjbhiddzOxKsOYiPOwIBAw==")
print(pub_key)
for i in range(len(c0_blocks)):
    # message size = i blocks long and N = len - i
    c1 = b"".join(c1_blocks[:i] + c1_blocks[i+1:])
    c2 = b"".join(c2_blocks[:i] + c2_blocks[i+1:])
    n0 = len(c0_blocks) - i
    n1 = len(c1_blocks) - i
    n2 = len(c2_blocks) - i

    crack_message(c0,c1,c2,n0,n1,n2,pub_key)

