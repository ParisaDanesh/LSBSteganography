from PIL import Image
from Crypto.PublicKey import RSA
import hashlib
import math
from base64 import b64decode,b64encode
from string import digits

def bin2str(txt):
    strText = ''.join(chr(int(txt[i * 8:i * 8 + 8], 2)) for i in range((len(txt) // 8)))
    return strText #.decode("UTF-8")

def str2bin(txt):
    b = [bin(ord(letter)) for letter in txt]
    a = ''.join([item[2:].rjust(8, '0') for item in b])
    return a
############################hash function###############################

def hashText(txt):
    hashedTxt = hashlib.md5(txt)
    """
            size and binary of hash:
                    print ("bin is :" , a)
                    print ("size : ",len(a))
    """
    return hashedTxt.hexdigest()


##########################RSA functions#################################
PrivateKeyFile = 'privateKey.pem'
PublicKeyFile  = 'publicKey.pem'

def generateKeys(password,keySize):
    privateKey = RSA.generate(int(keySize))                                      #make a private key
    encryptedKey = privateKey.exportKey(format='PEM', passphrase=password)  #encrypt private key with my own password
    with open(PrivateKeyFile, 'w') as file:                                 #save private key in a file
        file.write(encryptedKey)

    publicKey = privateKey.publickey()                                      #make public key from private key
    with open(PublicKeyFile, 'w') as file:                                  #save public key in a file
        file.write(publicKey.exportKey())

    print "Keys Generated Successfully"

def getPrivateKey(password):
    try:
        with open(PrivateKeyFile, 'r') as file:
            return RSA.importKey(file.read(),passphrase=password)
    except Exception as e:
        return None

def getPublicKey():
    try:
        with open(PublicKeyFile,'r') as file:
            return RSA.importKey(file.read())
    except Exception as e:
        return None

def decryptData(data, privateKey, keySize):
    try:
        dataLen = len(data)
        blkSize = int(keySize) / 8
        blk = dataLen / blkSize
        # return blk
        if (dataLen % blkSize != 0):
            blk += 1

        decData = ""
        for i in range(0, blk):
            tmp = privateKey.decrypt(data[i * blkSize:(i + 1) * blkSize])
            decData += tmp
        return decData
    except Exception as e:
        return None

def encryptData(data, publicKey, keySize):
    dataLen = len(data)
    blkSize = int(keySize) / 8
    blk = dataLen / blkSize
    # return blk
    if (dataLen % blkSize != 0):
        blk += 1
    dataEnc = ""
    for i in range(0, blk):
        tmp = publicKey.encrypt(data[i * blkSize:(i + 1) * blkSize], None)[
            0]  # to encrypt your data with public key
        dataEnc += tmp
    return dataEnc


########################################################################
"""
    bin2dec() : convert new data to decimal for saving new pixel
    str2bin() : convert to binary dg :|
    replace_str_index : to replace pixel data with your pixel
"""
def bin2dec(binary):
    decimal = 0
    for digit in binary:
        if digit in ['0','1']:
            decimal = decimal * 2 + int(digit)
    return decimal

def replace_str_index(text,index=0,replacement=''):
    return '%s%s%s'%(text[:index],replacement,text[index+1:])

#########################################################################
newData = []

def putDataSize(msgLen, binMsgLen , pixels):
    x = 0
    # nahayat 4 pixel migire -> faghat 3 bite kam arzeshe har pixel estefade mishe
    if (msgLen <= 3000):
        for i in range(0, len(binMsgLen), 3):
            RGB = pixels[x]
            print ("pixel", x, " : ", RGB)
            r = bin(RGB[0])
            if r in ["0b0","0b1"]:
                r = r.ljust(10,"0")
            print ("old r :", r)
            r = replace_str_index(r, 9, binMsgLen[i])
            print ("new r :", r)
            decr = bin2dec(r[2:])
            if (i + 1 != len(binMsgLen)):
                g = bin(RGB[1])
                if g in ["0b0", "0b1"]:
                    g = g.ljust(10, "0")
                print ("old g :", g)
                g = replace_str_index(g, 9, binMsgLen[i + 1])
                print ("new g :", g)
                decg = bin2dec(g[2:])
                if (i + 2 != len(binMsgLen)):
                    b = bin(RGB[2])
                    if b in ["0b0", "0b1"]:
                        b = b.ljust(10, "0")
                    print ("old b :", b)
                    b = replace_str_index(b, 9, binMsgLen[i + 2])
                    print ("new b :", b)
                    decb = bin2dec(b[2:])
                else:
                    decb = bin2dec(b[2:])
            else:
                decg = bin2dec(g[2:])

            newData.append((decr, decg, decb))
            print ("new pixel", x, " : ", (decr, decg, decb))
            x = x + 1
    else:
        exit()

def embedData(pixels ,finalData ):
    finalDataLen = len(finalData)
    x = 4
    for i in range(0, finalDataLen, 3):
        RGB = pixels[x]
        # print ("pixel", x, " : ", RGB)
        r = bin(RGB[0])
        if r in ["0b0", "0b1"]:
            r = r.ljust(10, "0")
        # print ("old r :", r)
        r = replace_str_index(r, 9, finalData[i])
        # print ("new r :", r)
        decr = bin2dec(r[2:])
        if (i + 1 != finalDataLen):
            g = bin(RGB[1])
            if g in ["0b0", "0b1"]:
                g = g.ljust(10, "0")
            # print ("old g :", g)
            g = replace_str_index(g, 9, finalData[i + 1])
            # print ("new g :", g)
            decg = bin2dec(g[2:])
            if (i + 2 != finalDataLen):
                b = bin(RGB[2])
                if b in ["0b0", "0b1"]:
                    b = b.ljust(10, "0")
                # print ("old b :", b)
                b = replace_str_index(b, 9, finalData[i + 2])
                # print ("new b :", b)
                decb = bin2dec(b[2:])
            else:
                decb = bin2dec(b[2:])
        else:
            decg = bin2dec(g[2:])
        # pixels[i] = (decr, decg, decb)
        newData.append((decr, decg, decb))
        x = x + 1
    for j in range(x, len(pixels)):
        newData.append(pixels[j])

##############################extract############################


def getMsgSize(newpix , keySize):
    # 4ta pixel ro mikham
    extractedData = ""
    x=0
    for i in range(x,4):
        newRGB = newpix[i]
        # print "pixel[",i,"] :"
        # print "     r:",bin(newRGB[0])
        # print "     g:",bin(newRGB[1])
        # print "     b:",bin(newRGB[2])
        for j in range(0,3):
            extracbit = bin(newRGB[j])
            if extracbit in ["0b0","0b1"]:
                extracbit = extracbit.ljust(10,"0")
            # print "      extracbit:",extracbit
            extractedData += extracbit[9]
        # print "      extractedData", extractedData
    return extractedData

def extractData(newpix , msgSize , keySize ):
    # print int(keySize)
    dataLen = int(msgSize,2)+32
    # print dataLen
    blkSize = int(keySize) / 8
    blk = dataLen / blkSize
    if (dataLen % blkSize != 0):
        blk += 1
    print "blk :",blk
    # print blk*int(keySize)
    pixSize = int(math.ceil((blk*keySize)/3.0))
    print "PIXEL",pixSize
    pixSize += 4
    # print "pixSize:",pixSize
    x = 4
    extract = ""
    for i in range(x,pixSize): #pixSize+1
        newRGB = newpix[i]
        for j in range(0, 3):
            extracbit = bin(newRGB[j])
            if extracbit in ["0b0","0b1"]:
                extracbit = extracbit.ljust(10,"0")
            # print "      extracbit:", extracbit
            extract += extracbit[9]
    print i
    return extract



def extractHash(newpix , msgSize , keySize ):
    # print int(keySize)
    dataLen = int(msgSize,2)+32
    # print dataLen
    blkSize = int(keySize) / 8
    blk = dataLen / blkSize
    if (dataLen % blkSize != 0):
        blk += 1
    print "blk :",blk
    # print blk*int(keySize)
    pixSize = int(math.ceil((blk*keySize)/3.0))
    print "PIXEL",pixSize
    pixSize += 4
    # print "pixSize:",pixSize
    x = pixSize+256
    extract = ""
    for i in range(pixSize,x): #pixSize+1
        newRGB = newpix[i]
        for j in range(0, 3):
            extracbit = bin(newRGB[j])
            if extracbit in ["0b0","0b1"]:
                extracbit = extracbit.ljust(10,"0")
            extract += extracbit[9]
    print i
    return extract

if __name__ == "__main__":
    image = Image.open("2.png")
    # msg = raw_input("enter your msg(max size 3000char): ")     #ye counter bezar
    msg ="parisa danesh"# "A"*3000
    """
        khob axo msg ro gereftim , hala bia sizesho too 2 ta pixele
         aval benevisim
    """

    msgLen = len(msg)
    binMsgLen = bin(msgLen)    #len(msg) int has
    print len(binMsgLen[2:])
    if (len(binMsgLen[2:]) != 12):   # :TODO inja mikham har andaze binMsgLen i has , 12 bitish kone !!!!
        a = binMsgLen[2:].rjust(12,'0')
        binMsgLen = "0b{}".format(a)
    # exit(0)

    # print "new",len(binMsgLen)
    pixels = list(image.getdata())

    # validation tedad pix aye ax ba max character

    maxpix = 8366 # baraye har pixel 3 bit + 4 pix bara size

    """
         noooooooowwww , start to save data in image
         first -> get hash of data
         enc -> enc data+hash
         then get hash of enc
         then convert it to binary
         then embed it :|
     """
    if (len(pixels) > maxpix):
        print "ghable rikhtan too ax:",binMsgLen[2:]
        putDataSize(msgLen, binMsgLen[2:], pixels)
        # # get hash of data
        # hashTxt = hashText(msg)
        #
        # ALIHASH = str2bin(hashTxt)
        #
        # MsgOHash = msg+hashTxt
        # # get pass and enc msg+hashTxt
        # password = raw_input("Enter Your Password: ")
        # # generateKeys(password , keySize=4096)
        # encData = encryptData(MsgOHash,getPublicKey(), keySize=4096)
        # encHash = hashText(encData)
        # ALIHASH = str2bin(encHash)
        # finalData = encData+encHash
        # binFinalData = str2bin(finalData)
        # ALITMP = binFinalData
        # print ALITMP
        # embedData(pixels, binFinalData )
        # # print "\n\nnew data(araye ghablaz rikhtan too pixel axe jadid) :\n",newData[:4]
        # newImage = Image.new(image.mode ,image.size)
        # newImage.putdata(newData)
        # # print "newpix(rikhtam too ax vali ghable save):\n",list(newImage.getdata())[:4]
        # newImage.save("newpic.png")
        #
        # """
        #     now you hide your data in pic!
        #     now we want to extract data from pic
        # """
        # newpic = Image.open("newpic.png")
        # newpix = list(newpic.getdata())
        # # print "newpic pixel(after saving) :\n",newpix[:4]
        # msgSize = getMsgSize(newpix,keySize=4096)
        # # print msgSize
        # binextract = extractData(newpix , msgSize , keySize=4096)
        # ALITMP_ = binextract
        # # extract = bin2str(binextract)
        # decData = decryptData(bin2str(binextract), getPrivateKey(password), keySize=4096)
        #
        # print ALITMP_
        # decDataLen = len(decData)-256
        # finalDecData = decData[:decDataLen]
        # print finalDecData
        # # print "0110011111110011001100110001001100000011010001100110011000110011100000110111011000100110010100110010011000110110010001100011011001000011001100110010001100100110001100111001011000100110001001100110011000100011100100110101011000110011100000110011001100110110000100110010"
        # # print ALIHASH[1:]

        # # test by ali , Correct
        print "len hash:",len(hashText(msg))
        print "len msg:",len(msg)
        msg = msg+hashText(msg)
        print "len finalmsg:",len(msg)
        e = encryptData(msg,getPublicKey(),4096)
        print str2bin(e)
        Len = len(msg)-32
        binMSG = str2bin(e+hashText(e))
        ###########################################
        # TODO: Here Set Your Binary(binMSG) To Picture

        # print "PIXELS",pixels
        # bw cheshe , khyli lag dare

        embedData(pixels,binMSG)#1

        newImage = Image.new(image.mode ,image.size)
        newImage.putdata(newData)
        # print "newpix(rikhtam too ax vali ghable save):\n",list(newImage.getdata())[:4]
        newImage.save("newpic.png")

        # TODO: Here Extract Binary From Picture to(binFromPicture)
        newpic = Image.open("newpic.png")
        newpix = list(newpic.getdata())
        # print newpix
        msgSize = getMsgSize(newpix, keySize=4096)
        print "msg size :",msgSize
        print "msg size :",int(msgSize,2)
        binFromPicture = extractData(newpix, msgSize, keySize=4096)
        # binFromPicture = ""

        # print len(binMSG)
        # Ekhtelaf 268 (WTF?!)
        # print binMSG
        print binFromPicture
        # print len("0011111110011001100110001001100000011010001100110011000110011100000110111011000100110010100110010011000110110010001100011011001000011001100110010001100100110001100111001011000100110001001100110011000100011100100110101011000110011100000110011001100110110000100110010")

        # exit(0)

        ###########################################
        # e = bin2str(binFromPicture)

        h = extractHash(newpix, msgSize , keySize=4096)

        d = decryptData(bin2str(binFromPicture),getPrivateKey("parisa"),4096)
        if (d != None):
            print d[:Len]
            print len(d[:Len])
        else:
            print d
        # print "hash e retrieve: ", d[Len:]
        # print "hash e msg :", hashText(d[:Len])
        if (hashText(d[:Len]) == d[Len:]):
            print "hash e msg: " , d[Len:]
        else:
            print "crash"

        print "hashe enc before :" , str2bin(hashText(e))
        print "hashe enc after :", "01"+h[0:len(str2bin(hashText(e)))-2]
        # print decData[:finalLen]
    else:
        exit()

