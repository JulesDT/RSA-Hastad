import sys
import binascii
from Crypto.PublicKey import RSA
from base64 import b64decode

if (len(sys.argv)<7):
    print "\t\n\nArg error: python rsaHastad.py <n0 File> <n1 File> <n2 File> <c0 File> <c1 File> <c2 File> [--decimal/--hex/--b64] [-v/--verbose]\n\n"
    exit()

print "\n"

print "\t~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
print "\t        RSA Hastad Attack         "
print "\t         JulesDT -- 2016          "
print "\t         License GNU/GPL          "
print "\t~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"


def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
 
    for n_i, a_i in zip(n, a):
        p = prod / n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod
 
 
def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a / b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1

def find_invpow(x,n):
    high = 1
    while high ** n < x:
        high *= 2
    low = high/2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1

def parseC(argv, index, verbose):
    import string
    file = open(argv[index],'r')
    cmd = ' '.join(argv)
    fileInput = ''.join(file.readlines()).strip()
    if '--decimal' in cmd:
        if verbose:
            print "##"
            print "##",fileInput
            print "## Considered as decimal input"
            print "##"
        return long(fileInput)
    elif '--hex' in cmd:
        if verbose:
            print "##"
            print "##",fileInput
            print "## Considered as hexadecimal input"
            print "##"
        return long(fileInput,16)
    elif '--b64' in cmd:
        if verbose:
            print "##"
            print "##",fileInput
            print "## Considered as base64 input"
            print "##"
        return long(binascii.hexlify(binascii.a2b_base64(fileInput)),16)
    else:
        try:
            fileInput = long(fileInput)
            if verbose:
                print "##"
                print "##",fileInput
                print "## Guessed as decimal input"
                print "##"
            return long(fileInput)
        except ValueError:
            if all(c in string.hexdigits for c in fileInput):
                if verbose:
                    print "##"
                    print "##",fileInput
                    print "## Guessed as hexadecimal input"
                    print "##"
                return long(fileInput,16)
            else:
                if verbose:
                    print "##"
                    print "##",fileInput
                    print "## Guessed as base64 input"
                    print "##"
                return long(binascii.hexlify(binascii.a2b_base64(fileInput)),16)
            pass

def parseN(argv,index):
    file = open(argv[index],'r')
    fileInput = ''.join(file.readlines()).strip()
    try:
        fileInput = long(fileInput)
        return fileInput
    except ValueError:
        from Crypto.PublicKey import RSA
        return long(RSA.importKey(fileInput).__getattr__('n'))
        pass


if __name__ == '__main__':
    e = 3
    cmd = ' '.join(sys.argv)
    if '-v' in cmd or '--verbose' in cmd:
        verbose = True
    else:
        verbose = False
    n0 = parseN(sys.argv,1)
    n1 = parseN(sys.argv,2)
    n2 = parseN(sys.argv,3)
    
    c0 = parseC(sys.argv,4,verbose)
    c1 = parseC(sys.argv,5,verbose)
    c2 = parseC(sys.argv,6,verbose)
    n = [n0,n1,n2]
    a = [c0,c1,c2]

    result = (chinese_remainder(n, a))
    resultHex = str(hex(find_invpow(result,3)))[2:-1]
    print ""
    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    print "Decoded Hex :\n",resultHex
    print "---------------------------"
    print "As Ascii :\n",resultHex.decode('hex')
    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
