# Set up parameters
DEGREE = 10  # Degree of the polynomial
BITSIZE = 64  # Bit size of the prime
p = 17612245458813196901  # Example prime modulus
points = [
    (16061925794087304359, 3444278253034665517),
    (6871315336358637160, 11861014588192027226),
    (14150311099047293307, 2402653507838990272),
    (303170884658933280, 794601646948892672),
    (17145919552714930582, 13309774665470604164),
    (12698334331143983436, 13651509895043033813),
    (11793545420017986825, 16931419170946022363),
    (11577968954367590970, 12254344053005718638),
    (9639075804468246787, 7648734507154237436),
    (2169039299899362595, 16228228033180123918)
]  # Provided points

# Sage code to set up the matrix, similar to the signature approach

nbCols = DEGREE + 2
nbRows = nbCols
Aspace = MatrixSpace(QQ, nbRows, nbCols)

A = copy(Aspace.identity_matrix())

print(A)

A = A*p
B = p // pow(2,16)

A[ - 2,  - 2] = B / p
A[ - 1,  - 1] = B

# Fill matrix A with polynomial terms and moduli
for i, (x_i, y_i) in enumerate(points):
    for d in range(DEGREE + 1):
        A[i, d] = x_i^d  # Fill polynomial terms

    A[i, -2] = -p  # Adjust modulus column
    A[i, -1] = y_i  # Offset by y_i, as with signatures


M = A.LLL()

for v in M:
    print(v)
    if v[-1] == B:
        c0 = int(v[0])  # The constant term, representing the secret
        print("Recovered constant term (secret):", c0)
        break
