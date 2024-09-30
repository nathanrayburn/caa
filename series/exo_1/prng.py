import secrets
def genBits(nbBits): 
    
    p = 14219462995139870823732990991847116988782830807352488252401693038616204860083820490505711585808733926271164036927426970740721056798703931112968394409581
    g = 13281265858694166072477793650892572448879887611901579408464846556561213586303026512968250994625746699137042521035053480634512936761634852301612870164047
    x = int(secrets.token_hex(16),16)#16 bytes of pure randomness
    ret = 0
    ths = round((p-1)/2)
    
    for i in range(nbBits):
        x = pow(g,x,p)
        if x > ths: # La condition est inversé  et ne retourne pas 0 ou 1 suivant la condition
                    # Mathématiquement, nous avons x qui est parfois plus petit et donc on n'addition pas beaucoup de valeurs.
                    # Donc la sum est souvent très petit parce que dans le range de 16 bytes
            print(i)
            ret += 2**i
    return ret

if __name__== "__main__":
  print("{:0256x}".format(genBits(1024)))
