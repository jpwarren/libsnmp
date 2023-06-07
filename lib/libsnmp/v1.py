# $Id$
# $Revision$
#
#    libsnmp - a Python SNMP library
#    Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>
#
# SNMPv1 related functions

import queue
import time

from libsnmp import asynrole
from libsnmp.rfc1157 import *

log = logging.getLogger('v1.SNMP')
log.setLevel(logging.INFO)


class SNMP(asynrole.Manager):
    nextRequestID = 0  # global counter of requestIDs

    def __init__(self, interface=('0.0.0.0', 0), queueEmpty=None, trapCallback=None, timeout=0.25):
        """ Create a new SNMPv1 object bound to localaddr
            where localaddr is an address tuple of the form
            ('server', port)
            queueEmpty is a callback of what to do if I run out
            of stuff to do. Default is to wait for more stuff.
        """
        self.queueEmpty = queueEmpty
        self.outbound = queue.Queue()
        self.callbacks = {}

        # What to do if we get a trap
        self.trapCallback = trapCallback

        # initialise as an asynrole manager
        asynrole.Manager.__init__(self, (self.receiveData, None), interface=interface, timeout=timeout)

        try:
            # figure out the current system uptime

            pass

        except:
            raise

    def assignRequestID(self):
        """ Assign a unique requestID 
        """
        reqID = self.nextRequestID
        self.nextRequestID += 1
        return reqID

    def createGetRequestPDU(self, varbindlist):
        reqID = self.assignRequestID()
        pdu = Get(reqID, varBindList=varbindlist)
        return pdu

    def createGetNextRequestPDU(self, varbindlist):
        reqID = self.assignRequestID()
        pdu = GetNext(reqID, varBindList=varbindlist)
        return pdu

    def createGetRequestMessage(self, oid, community='public'):
        """ Creates a message object from a pdu and a
            community string.
        """
        objID = ObjectID(oid)
        val = Null()
        varbindlist = VarBindList([VarBind(objID, val)])
        pdu = self.createGetRequestPDU(varbindlist)
        return Message(community=community, data=pdu)

    def createGetNextRequestMessage(self, varbindlist, community='public'):
        """ Creates a message object from a pdu and a
            community string.
        """
        pdu = self.createGetNextRequestPDU(varbindlist)
        return Message(community=community, data=pdu)

    def createTrapMessage(self, pdu, community='public'):
        """ Creates a message object from a pdu and a
            community string.
        """
        return Message(community=community, data=pdu)

    def createTrapPDU(self, varbindlist, enterprise='.1.3.6.1.4', agentAddr=None, genericTrap=6, specificTrap=0):
        """ Creates a Trap PDU object from a list of strings and integers
            along with a varBindList to make it a bit easier to build a Trap.
        """
        ent = ObjectID(enterprise)
        if not agentAddr:
            agentAddr = self.getsockname()[0]
        agent = NetworkAddress(agentAddr)
        gTrap = GenericTrap(genericTrap)
        sTrap = Integer(specificTrap)
        ts = TimeTicks(self.getSysUptime())

        pdu = TrapPDU(ent, agent, gTrap, sTrap, ts, varbindlist)
        #        log.debug('v1.trap is %s' % pdu)
        return pdu

    def snmpGet(self, oid, remote, callback, community='public'):
        """ snmpGet issues an SNMP Get Request to remote for
            the object ID oid 
            remote is a tuple of (host, port)
            oid is a dotted string eg: .1.2.6.1.0.1.1.3.0
        """
        msg = self.createGetRequestMessage(oid, community)

        # add this message to the outbound queue as a tuple
        self.outbound.put((msg, remote))
        # Add the callback to my dictionary with the requestID
        # as the key for later retrieval
        self.callbacks[int(msg.data.requestID)] = callback
        return msg.data.requestID

    def snmpGetNext(self, varbindlist, remote, callback, community='public'):
        """ snmpGetNext issues an SNMP Get Next Request to remote for
            the varbindlist that is passed in. It is assumed that you
            have either built a varbindlist yourself or just pass
            one in that was previously returned by an snmpGet or snmpGetNext
        """
        msg = self.createGetNextRequestMessage(varbindlist, community)

        # add this message to the outbound queue as a tuple
        self.outbound.put((msg, remote))
        # Add the callback to my dictionary with the requestID
        # as the key for later retrieval
        self.callbacks[int(msg.data.requestID)] = callback
        return msg.data.requestID

    def snmpSet(self, varbindlist, remote, callback, community='public'):
        """ An snmpSet requires a bit more up front smarts, in that
            you need to pass in a varbindlist of matching OIDs and
            values so that the value type matches that expected for the
            OID. This library does not care about any of that stuff.

        """
        reqID = self.assignRequestID()
        pdu = GetNext(reqID, varBindList=varbindlist)
        msg = Message(community=community, data=pdu)

        # add this message to the outbound queue as a tuple
        self.outbound.put((msg, remote))
        # Add the callback to my dictionary with the requestID
        # as the key for later retrieval
        self.callbacks[int(msg.data.requestID)] = callback
        return msg.data.requestID

    def snmpTrap(self, remote, trapPDU, community='public'):
        """ Queue up a trap for sending
        """
        msg = self.createTrapMessage(trapPDU, community)

        self.outbound.put((msg, remote))

    def createSetRequestMessage(self, varBindList, community='public'):
        """ Creates a message object from a pdu and a
            community string.
        """

    def receiveData(self, manager, cb_ctx, xxx_todo_changeme, xxx_todo_changeme1):
        """ This method should be called when data is received
            from a remote host.
        """
        (data, src) = xxx_todo_changeme
        (exc_type, exc_value, exc_traceback) = xxx_todo_changeme1
        if exc_type is not None:
            raise exc_type(exc_value)

        # perform the action on the message by calling the
        # callback from my list of callbacks, passing it the
        # message and a reference to myself

        try:
            # Decode the data into a message
            msg = Message().decode(data)

            # Decode it based on what version of message it is
            if msg.version == 0:
                if __debug__: log.debug('Detected SNMPv1 message')

            else:
                log.error('Unknown message version %d detected' % msg.version)
                log.error('version is a %s' % msg.version())
                raise ValueError('Unknown message version %d detected' % msg.version)

            # Figure out what kind of PDU the message contains
            if isinstance(msg.data, PDU):
                #               if __debug__: log.debug('response to requestID: %d' % msg.data.requestID)
                self.callbacks[int(msg.data.requestID)](self, msg)

                # remove the callback from my list once it's done
                del self.callbacks[int(msg.data.requestID)]

            elif isinstance(msg.data, TrapPDU):
                if __debug__: log.debug('Detected an inbound Trap')
                self.trapCallback(self, msg)

            else:
                if __debug__: log.debug('Unknown message type')

        # log any errors in callback
        except Exception as e:
            #            log.error('Exception in callback: %s: %s' % (self.callbacks[int(msg.data.requestID)].__name__, e) )
            log.error('Exception in receiveData: %s' % e)
            raise

    def enterpriseOID(self, partialOID):
        """ A convenience method to automagically prepend the
            'enterprise' prefix to the partial OID
        """
        return '.1.3.6.1.2.1.' + partialOID

    def run(self):
        """ Listen for incoming request thingies
            and send pending requests
        """
        while True:
            try:
                # send any pending outbound messages
                request = self.outbound.get(0)
                self.send(request[0].encode(), request[1])

            except queue.Empty:
                if self.queueEmpty is not None:
                    self.queueEmpty(self)
                pass

                # check for inbound messages
                self.poll()

                time.sleep(0.1)

    def getSysUptime(self):
        """ This is a pain because of system dependence
            Each OS has a different way of doing this and I
            cannot find a Python builtin that will do it.
        """
        try:
            ##
            ## The linux way
            ##
            uptime = open('/proc/uptime').read().split()
            upsecs = int(float(uptime[0]) * 100)

            return upsecs

        except:
            return 0
