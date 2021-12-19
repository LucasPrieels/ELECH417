import math
import random


def get_prime():
    # Gets a prime number from file
    prime = random.choice(list(open('prime.txt')))
    return int(prime)


def egcd1(x, y):
    # Euclid's algorithm for determining the greatest common divisor
    while y != 0:
        x, y = y, x % y
    return x


def is_coprime(x, y):
    # Check if two numbers are relatively primes
    return egcd(x, y) == 1


def modulus(p, q):
    n = p * q
    return n


def toitent(p, q):
    z = (p - 1) * (q - 1)
    print('saltzez')
    return z


def get_e(p, q):
    # Sets a e such as ecgd(e,z) = 1
    ## Pourrait être amélioré
    z = toitent(p, q)
    e = random.randrange(1, z)

    while is_coprime(e, z) != 1:
        e = random.randrange(1, z)

    return e


def egcd(e, z):
    # Euclid's algo -> find e (relative prime numbers)
    while z != 0:
        t = z
        z = e % z
        e = t
    return e


def modInverse(a, m):
    # modular inverse using extended
    # Euclid algorithm a = e, m = z

    # Returns modulo inverse of a with
    # respect to m using extended Euclid
    # Algorithm Assumption: a and m are
    # coprimes, i.e., gcd(a, m) = 1
    m0 = m
    y = 0
    x = 1

    if m == 1:
        return 0

    while a > 1:
        # q is quotient
        q = a // m

        t = m

        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y

        # Update x and y
        y = x - q * y
        x = t

    # Make x positive
    if x < 0:
        x = x + m0

    return x


def key_generation():
    p = get_prime()
    q = get_prime()

    n = modulus(p, q)
    z = toitent(p, q)
    e = get_e(p, q)
    d = modInverse(e, z)
    return (e, n), (d, n)


def encrypt(pub_key, n_text):
    # Encryption algorithm
    e, n = pub_key
    x = []
    m = 0
    for i in n_text:
        if (i.isupper()):
            m = ord(i) - 65
            c = (m ** e) % n
            x.append(c)
        elif (i.islower()):
            m = ord(i) - 97
            c = (m ** e) % n
            x.append(c)
        elif (i.isspace()):
            spc = 400
            x.append(400)
    return x


def decrypt(priv_key, c_text):
    d, n = priv_key
    txt = str()
    for i in c_text:
        txt += str(i) + ','
    txt = txt[0:len(txt)-1]
    print(txt)
    txt = txt.split(',')
    x = ''
    m = 0
    print(txt)
    for i in txt:
        if (i == '400'):
            x += ' '
        else:
            m = (int(i) ** d) % n
            m += 65
            c = chr(m)
            x += c
    return x

# Test

message = input("Enter your message :")
print("Your message is:", message)

public, private = key_generation()
print("Public key is : ", public)
print("Private key is : ", private)

# Cipher the message
encrypted_msg = encrypt(public, message)
print("Encrypted message : ", encrypted_msg)

# Decipher message
decrypted_msg = decrypt(private, encrypted_msg)
print("Decrypted message : ", decrypted_msg)







