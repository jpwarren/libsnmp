import sys
import asyncore
import types

from libsnmp import rfc1155
from libsnmp import rfc1157
from libsnmp import role

class manager(asyncore.dispatcher):
    
    def __init__(self, (cb_fun, cb_ctx), dst=(None, 0), interface=('0.0.0.0', 0)):
        
        if not callable(cb_fun):
            raise ValueError('Non-callable callback function')
        
        self.cb_fun = cb_fun
        self.cb_ctx = cb_ctx
        
        asyncore.dispatcher.__init__(self)
        
        self.manager = role.manager(dst, interface)
        
        self.set_socket(self.manager.open())
        return
    
    def send(self, req, dst=(None, 0)):
        self.manager.send(req, dst)
        return
    
    def handle_read(self):
        (response, src) = self.manager.read()
        self.cb_fun(self, self.cb_ctx, (response, src), (None, None, None))
        return
    
    def writable(self):
        return 0
    
    def handle_connect(self):
        return
    
    def handle_close(self):
        self.manager.close()
        return
    
    def handle_error(self, exc_type=None, exc_value=None, exc_traceback=None):
        if exc_type is None or exc_value is None or exc_traceback is None:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            pass
        if type(exc_type) == types.ClassType and issubclass(exc_type, ValueError):
            self.cb_fun(self, self.cb_ctx, (None, None), (exc_type, exc_value, exc_traceback))
        else:
            raise
        
        return
    pass

