# vim: sts=4 sw=4 et

import vlog
log = vlog.Vlog("dbg")

def sane_color(x):
    r=""
    for i in x:
        j = ord(i)
        if (j < 32) or (j >= 127):
            r=r+"."
        else:
            r=r+i
    return r

def hexdump(x):
    x=str(x)
    l = len(x)
    i = 0
    while i < l:
        print "%04x  " % i,
        for j in range(16):
            if i+j < l:
                print "%02X" % ord(x[i+j]),
            else:
                print "  ",
            if j%16 == 7:
                print "",
        print " ",
        print sane_color(x[i:i+16])
        i += 16
