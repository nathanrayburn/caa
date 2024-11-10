import hashlib
def LLL(B):
    message = b"ecdsa.c"
    h = hashlib.sha256(message).hexdigest()
    n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

    with open("message.txt", "r") as file:
        lines = [int(line.strip(), 16) for line in file]
    signatures = [(lines[i], lines[i+1]) for i in range(0, len(lines), 2)]

    length = len(signatures) + 2
    M = MatrixSpace(QQ, length, length)
    A = copy(M.identity_matrix())

    for x in range(length - 2):
        ti = (signatures[x][0] / signatures[x][1]) % n
        ai = (-(int(h, 16) / signatures[x][1])) % n

        A[x, x] = n
        A[length - 1, x] = ai
        A[length - 2, x] = ti

    A[length - 1, length - 1] = B
    A[length - 2, length - 2] = B / n

    # Apply LLL
    R = A.LLL()

    # Calculate the private key from the LLL result
    for row in R:
        print("Row:", row)  # Debugging line to see the rows in R
        if row[-1] == B:
            a = ZZ((-row[-2] * n / B) % n)
            print("Value of a:", a)
            print("Value of -a mod n:", (-a) % n)
            return a, (-a) % n  # Return both values

    # If no valid row is found, return None, None
    print("No valid row found with row[-1] == B")
    return None, None

# Main loop
for i in range(2, 256):
    print("Iteration:", i) 
    a, inv_a = LLL(pow(2, i))
    
    # Skip iteration if LLL returned None
    if a is None or inv_a is None:
        print("Skipping iteration due to None return")
        continue
    
    if key == a or key == inv_a:
        print("Found boundary")
        break

