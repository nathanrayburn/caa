# Notes

## Timeline 

![alt text](image.png)

## Randomness

What are the risks if they are not perfectly random ?

We can brute force the range.
If there is a probabability that its one or 0. We can start directly with 1 for an example and add zeros on the way down.

### Random number gen

A random number generator is a physical or computiation device that generates a sequence of numbers that appear to be random.

### Statistical tests

![alt text](image-1.png)

### True Random Number Generators

A true random number generator is an apparatus that generators random numbers from a physical process.
![alt text](image-2.png)

### Bad TRNGS

![alt text](image-3.png)


### Bit Distribution properties

- Bias of a bit
- Independent bits

### Randomness Extraction Neuann
![alt text](image-4.png)

### PRNG

PRGN is deterministic.

Is a deterministi algorith whose aim is to generate a sequence of numbers exhibiting good statistical properties.

### Bad PRNGs : Mersenne Twiser.

![alt text](image-5.png)

![alt text](image-6.png)

![alt text](image-7.png)


### Cryptographically Secure PRNGs

![alt text](image-8.png)

### Blum Blum Shub PRNG

![alt text](image-9.png)
The issue is that the person that generates p and q must throws it away because it can be used as a backdoor.

### Blum-Micali PRNG

![alt text](image-10.png)

### Forward and Backward Security
![alt text](image-11.png)

### Backward Security

Backward security requires injecting fresh entropy.

Seeding, reseeding and value generation.

N'est pas 100% sure. Il faut utiliser un TRNG.

### Sources of Entropy

Avant le kernel 5.6 linux, dev random était blocant donc en utilisant le mouvement de la souris. Il fallait attendre qu'il y avait assez d'entropy dans le systeme.

dev/urandom qui est un cprng qui utilise le systeme de reseed. Il est non blocant, mais ça pouvait devenir deterministe. Le processus ID est utilisé pour généré les valeurs aléatoires. 

Il faut de l'entropy, et maintenant il bloque sur le systeme moderne.

### Intel's RDSEED and RDRAND

![alt text](image-12.png)

![alt text](image-13.png)

Dans chaque coeur, c'est un RDSEED different.

### RNRAND/RDSEED is not perfect

![alt text](image-14.png)

Il faut checker le carry flag pour savoir s'il y a eu un retour de valeur aléatoire.  Il faut lire le carry flag pour savoir si dans le registre.

### Pool of Entropy

![alt text](image-15.png)

**Dans les OS (maybe not windows)** : 

new = old xor data
Un attaquant peut retrouver le new et supprimé l'entropy du système s'il a accès à la ram.


**Ce qui se fait dans OpenSSL** :

new = Hash( old || data )

Ca empeche d'arriver à 0.


### Cryptographic PRNGs


![alt text](image-16.png)

### Hash_DRBG

![alt text](image-17.png)

![alt text](image-18.png)

### CTR_DRBG
![alt text](image-19.png)
![alt text](image-20.png)

### DUAL_EC_DRBG

![alt text](image-21.png)

Jamais utilisé.

### Randomness Generation in Practice

![alt text](image-22.png)

## Symmetric Primitives and modes of Operation

## Asymmetric primitives and Security Definitions

## Password-Based Cryptography and Key-derivation functions (KDF)

## Secret Shariung and Cryptographic Protocols


## TLS and Key Management


