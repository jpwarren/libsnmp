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

import socket
import logging
import time

from libsnmp import debug
from libsnmp import rfc1155
from libsnmp import rfc1157

log = logging.getLogger('v1.SNMP')

class manager:
    
    def __init__(self, dest, interface=('0.0.0.0', 0), socksize=0x10000):
        
        self.dest = dest
        self.interface = interface
        self.socket = None
        self.socksize = socksize
        self.request_id = 1
        
        return
    
    def __del__(self):
        self.close()
        return
    
    def get_socket(self):
        return self.socket
    
    def open(self):
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print self.interface
        self.socket.bind(self.interface)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.socksize)
        
        return self.socket
    
    def send(self, request, dst=(None, 0)):
        if not self.socket:
            self.open()
            pass
        self.socket.sendto(request, dst)
        return
    
    def read(self):
        if not self.socket:
            raise ValueError('Socket not initialized')
        
        (message, src) = self.socket.recvfrom(self.socksize)
        
        return (message, src)
    
    def close(self):
        if self.socket:
            self.socket.close()
            pass
        self.socket = None  
        return
    
    pass
