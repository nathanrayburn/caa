import secrets
from sage.all import is_prime, ZZ, GF

# Function to generate a generator (g) for a prime p such that it generates a cyclic group of p-1 elements
def generateGSpot(p):
    if not is_prime(p):
        raise ValueError("p must be a prime number")
    
    # Create a finite field Z/pZ
    F = GF(p)

    # Iterate over elements of the field to find a generator, skip 0
    for g in F:
        if g == 0:
            continue
        
        if g.multiplicative_order() == p - 1:  # Check if the order of g is p-1
            print("G spot:")
            print(int(g))
            
            return int(g)
    
    raise ValueError("No generator found")
# Function to generate random bits based on g and p
def genBits(nbBits): 
    p = 14219462995139870823732990991847116988782830807352488252401693038616204860083820490505711585808733926271164036927426970740721056798703931112968394409581
    g = generateGSpot(p)
    
    x = int(secrets.token_hex(16), 16)  # 16 bytes of pure randomness
    ret = 0
    ths = round((p-1)/2)
    
    for i in range(nbBits):
        x = pow(g, x, p)
        if x > ths:
            ret += 2**i
    
    return ret

if __name__ == "__main__":
    print("{:0256x}".format(genBits(1024)))
