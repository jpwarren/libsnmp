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
