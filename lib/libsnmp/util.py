# $Id$
# Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>
# All Rights Reserved
# 
# Some utility functions to help make life easier

def octetsToHex(octets):
    """ convert a string of octets to a string of hex digits
    """
    result = ''
    while octets:
        byte = octets[0]
        octets = octets[1:]
        result += "%.2x" % ord(byte)

    return result

def octetsToOct(octets):
    """ convert a string of octets to a string of octal digits
    """
    result = ''
    while octets:
        byte = octets[0]
        octets = octets[1:]
        result += "%.4s," % oct(ord(byte))

    return result

