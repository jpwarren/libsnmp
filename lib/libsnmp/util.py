# $Id$
# $Revision$
#
#    libsnmp - a Python SNMP library
#    Copyright (C) 2003 Unicity Pty Ltd <libsnmp@unicity.com.au>
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

