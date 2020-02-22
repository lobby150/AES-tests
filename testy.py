import struct
import time
from Crypto.Util import Counter
#AES - 128
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
key = 'abcdefghijklmnop'
iv = b'0000000000000000'
counter = Counter.new(128, initial_value=int(iv, 16))
print("Szyfrowanie plikow o wielkosci: 464KB, 8,11MB oraz 64,8MB\n")
print("Najpierw szyfrowanie i deszfrowanie ECB\n")
'''
cipher = AES.new(key.encode("utf8"), AES.MODE_ECB)
decipher = AES.new(key.encode("utf8"),AES.MODE_ECB)
maly = open("polMB.txt","r")
sredni = open("8MB.txt","r")
duzy = open("400MB.txt","r")
maly1 = maly.read()
sredni1 = sredni.read()
duzy1 = duzy.read()
maly_szyfr_start_ECB = time.time()
msg = cipher.encrypt(maly1.encode("utf8"))
maly_szyfr_stop_ECB = time.time() - maly_szyfr_start_ECB

maly_deszyfr_start_ECB = time.time()
msg1 = cipher.decrypt(msg)
maly_deszyfr_stop_ECB = time.time() - maly_deszyfr_start_ECB

print("Szyfrowanie malego pliku ECB: " + str(maly_szyfr_stop_ECB) + "\n")
print("Deszyfrowanie malego pliku ECB: " + str(maly_deszyfr_stop_ECB) + "\n")

sredni_szyfr_start = time.time()
msg2 = cipher.encrypt(sredni1.encode("utf8"))
maly_szyfr_stop = time.time() - sredni_szyfr_start

maly_deszyfr_start = time.time()
msg1 = cipher.decrypt(msg)
maly_deszyfr_stop = time.time() - maly_deszyfr_start
'''
maly = open("polMB.txt","r")
sredni = open("8MB.txt","r")
duzy = open("40MB.txt","r")

maly1 = maly.read()
sredni1 = sredni.read()
duzy1 = duzy.read()


def szyfrowanie_ECB(plik,key):

    cipher = AES.new(key.encode("utf8"), AES.MODE_ECB)
    start_time = time.time()
    msg = b64encode(cipher.encrypt(pad(plik.encode("utf8"),16)))
    end_time = time.time() - start_time
    print("Czas szyfrowania: " + str(end_time))
    return msg

def deszyfrowanie_ECB(plik,key):
    raw = b64decode(plik)
    decipher = AES.new(key.encode("utf8"), AES.MODE_ECB)
    start_time = time.time()
    msg = unpad(decipher.decrypt(raw),16)
    end_time = time.time() - start_time
    print("Czas deszyfrowania: " + str(end_time))
    return msg

def szyfrowanie_CBC(plik,key):
    cipher = AES.new(key.encode("utf8"),AES.MODE_CBC,iv)
    start_time = time.time()
    msg = b64encode(iv+cipher.encrypt(pad(plik.encode("utf8"),16)))
    end_time = time.time() - start_time
    print("Czas szyfrowania: " + str(end_time))
    return msg


def deszyfrowanie_CBC(plik,key):
    raw = b64decode(plik)
    decipher = AES.new(key.encode("utf8"), AES.MODE_CBC,iv)
    start_time = time.time()
    msg = unpad(decipher.decrypt(raw[16:]),16)
    end_time = time.time() - start_time
    print("Czas deszyfrowania: " + str(end_time))
    return msg

def szyfrowanie_OFB(plik,key):
    cipher = AES.new(key.encode("utf8"),AES.MODE_OFB,iv)
    start_time = time.time()
    msg = b64encode(iv + cipher.encrypt(pad(plik.encode("utf8"), 16)))
    end_time = time.time() - start_time
    print("Czas szyfrowania: " + str(end_time))
    return msg


def deszyfrowanie_OFB(plik,key):
    raw = b64decode(plik)
    decipher = AES.new(key.encode("utf8"), AES.MODE_OFB,iv)
    start_time = time.time()
    msg = unpad(decipher.decrypt(raw[16:]), 16)
    end_time = time.time() - start_time
    print("Czas deszyfrowania: " + str(end_time))
    return msg


def szyfrowanie_CFB(plik,key):
    cipher = AES.new(key.encode("utf8"),AES.MODE_CFB,iv)
    start_time = time.time()
    msg = b64encode(iv + cipher.encrypt(pad(plik.encode("utf8"), 16)))
    end_time = time.time() - start_time
    print("Czas szyfrowania: " + str(end_time))
    return msg


def deszyfrowanie_CFB(plik,key):
    raw = b64decode(plik)
    decipher = AES.new(key.encode("utf8"), AES.MODE_CFB,iv)
    start_time = time.time()
    msg = unpad(decipher.decrypt(raw[16:]), 16)
    end_time = time.time() - start_time
    print("Czas deszyfrowania: " + str(end_time))
    return msg


def szyfrowanie_CTR(plik,key):

    cipher = AES.new(key.encode("utf8"),AES.MODE_CTR,counter=counter)
    start_time = time.time()
    msg = b64encode(iv + cipher.encrypt(pad(plik.encode("utf8"), 16)))
    end_time = time.time() - start_time
    print("Czas szyfrowania: " + str(end_time))
    return msg


def deszyfrowanie_CTR(plik,key):
    raw = b64decode(plik)
    decipher = AES.new(key.encode("utf8"), AES.MODE_CTR,counter=counter)
    start_time = time.time()
    msg = unpad(decipher.decrypt(raw[16:]), 16)
    end_time = time.time() - start_time
    print("Czas deszyfrowania: " + str(end_time))
    return msg



("Maly plik ECB\t")
one =szyfrowanie_ECB(maly1,key)

#f1 = open("maly_ECB.txt","w+")
#f1.write(str(one))
x2=deszyfrowanie_ECB(one,key)


print("\nSredni plik ECB\t")
two = szyfrowanie_ECB(sredni1,key)
deszyfrowanie_ECB(two,key)

print("\nDuzy plik ECB\t")
three = szyfrowanie_ECB(duzy1,key)
deszyfrowanie_ECB(three,key)

print("\nSzyfrowanie i deszyfrowanie CBC\n")


print("Maly plik CBC\t")
four = szyfrowanie_CBC(maly1,key)

#f2 = open("maly_CBC.txt","w+")
#f2.write(str(four))
deszyfrowanie_CBC(four,key)


print("\nSredni plik CBC\t")
five = szyfrowanie_CBC(sredni1,key)
deszyfrowanie_CBC(five,key)

print("\nDuzy plik CBC\t")
six = szyfrowanie_CBC(duzy1,key)

deszyfrowanie_CBC(six,key)

print("\nSzyfrowanie i deszyfrowanie OFB\n")


print("Maly plik OFB\t")
seven = szyfrowanie_OFB(maly1,key)

#f3 = open("maly_OFB.txt","w+")
#f3.write(str(seven))
deszyfrowanie_OFB(seven,key)


print("\nSredni plik OFB\t")
eight = szyfrowanie_OFB(sredni1,key)
deszyfrowanie_OFB(eight,key)

print("\nDuzy plik OFB\t")
nine = szyfrowanie_OFB(duzy1,key)
deszyfrowanie_OFB(nine,key)


print("\nSzyfrowanie i deszyfrowanie CFB\n")


print("Maly plik CFB\t")
ten = szyfrowanie_CFB(maly1,key)

#f4 = open("maly_CFB.txt","w+")
#f4.write(str(ten))
deszyfrowanie_CFB(ten,key)


print("\nSredni plik CFB\t")
eleven = szyfrowanie_CFB(sredni1,key)
deszyfrowanie_CFB(eleven,key)

print("\nDuzy plik CFB\t")
twelve = szyfrowanie_CFB(duzy1,key)
deszyfrowanie_CFB(twelve,key)

print("\nSzyfrowanie i deszyfrowanie CTR\n")



print("Maly plik CTR\t")
thirteen = szyfrowanie_CTR(maly1,key)
#print(thirteen)
#f5 = open("maly_CTR.txt","w+")
#f5.write(str(thirteen))

deszyfrowanie_CTR(thirteen,key)
#print(a)


print("\nSredni plik CTR\t")
fourteen = szyfrowanie_CTR(sredni1,key)
deszyfrowanie_CTR(fourteen,key)

print("\nDuzy plik CTR\t")
fifteen = szyfrowanie_CTR(duzy1,key)

deszyfrowanie_CTR(fifteen,key)


#f = open("inne_CBC.txt","r+")
#s = f.read()
#a=deszyfrowanie_CBC(s,key)
#print(a)
## KILKA BLOKOW  ZOSTAJE ZMIENIONYCH

#a = open("inne_CFB.txt","r")
#s = a.read()
#z=deszyfrowanie_CFB(s,key)
#print(z)
## rowniez w CFB kilka blokow zostaje zmienionych

#p1 = open("inne_OFB.txt","r+")
#p2 = p1.read()
#z2 = deszyfrowanie_OFB(p2,key)
#print(z2)
#zmiana jednego bajtu w szyfrogramie, w trakcie deszyfrowania ulega bledowi tylko ten jeden bajt


#p6 = open("inne_CTR.txt","r")
#p7 = p6.read()
#z9 = deszyfrowanie_CTR(p7,key)
#print(z9)

##w CTR rowniez tak samo jak w OFB


#x1 = open("inne_ECB.txt","r+")
#x2 = x1.read()
#x3 = deszyfrowanie_ECB(x2,key)
#print(x3)
##zmiana w szyfrogramie metoda ECB powoduje znieksztalcenie kilka blokow