#coding:utf-8
# Embedded file name: secend.py

def secend():
    print "Welcome to Processor's Python Classroom Part 2!\n"
    print "Now let's start the origin of Python!\n"
    print 'Plz Input Your Flag:\n'
    enc = raw_input()
    lens = len(enc)
    enc1 = []
    enc2 = ''
    aaa = 'ioOavquaDb}x2ha4[~ifqZaujQ#'
    for i in range(lens):
        if i % 2 == 0:#2
            enc1.append(chr(ord(enc[i]) + 1))
        else:#1
            enc1.append(chr(ord(enc[i]) + 2))
     
    s1 = []
    for x in range(3):#encrypt the plain
        for i in range(lens):#
            if (i + x) % 3 == 0:#swap the position
                s1.append(enc1[i])
     
    enc2 = enc2.join(s1)
    if enc2 in aaa: #another way to judge equal
        print "You 're Right!"
    else:
        print "You're Wrong!"
        exit(0)