# $Id$
# Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>
# All Rights Reserved
#
# SNMPv1 related functions

import socket
import select
import logging
import Queue
import time
import os

from libsnmp import debug
from libsnmp import rfc1155
from libsnmp import rfc1157

log = logging.getLogger('v1.SNMP')

class SNMP:

    nextRequestID = 0L      # global counter of requestIDs

    def __init__(self, localaddr, queueEmpty=None, trapCallback=None, timeout=0.25):
        """ Create a new SNMPv1 object bound to localaddr
            where localaddr is an address tuple of the form
            ('server', port)
            queueEmpty is a callback of what to do if I run out
            of stuff to do. Default is to wait for more stuff.
        """
        self.timeout = timeout
        self.queueEmpty = queueEmpty
        self.outbound = Queue.Queue()
        self.callbacks = {}

        # What to do if we get a trap
        self.trapCallback = trapCallback

        try:
            # figure out the current system uptime
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind( localaddr )

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
        pdu = rfc1157.GetRequestPDU( reqID, varBindList=varbindlist )
        return pdu

    def createGetNextRequestPDU(self, varbindlist):
        reqID = self.assignRequestID()
        pdu = rfc1157.GetNextRequestPDU( reqID, varBindList=varbindlist )
        return pdu

    def createGetRequestMessage(self, oid, community='public'):
        """ Creates a message object from a pdu and a
            community string.
        """
        objID = rfc1155.ObjectID(stringval=oid)
        val = rfc1155.Null()
        varbindlist = rfc1157.VarBindList( [ rfc1157.VarBind(objID, val) ] )
        pdu = self.createGetRequestPDU( varbindlist )
        return rfc1157.Message( community=community, data=pdu )

    def createGetNextRequestMessage(self, varbindlist, community='public'):
        """ Creates a message object from a pdu and a
            community string.
        """
        pdu = self.createGetNextRequestPDU( varbindlist )
        return rfc1157.Message( community=community, data=pdu )

    def createTrapMessage(self, pdu, community='public'):
        """ Creates a message object from a pdu and a
            community string.
        """
        return rfc1157.Message( community=community, data=pdu )

    def createTrapPDU(self, varbindlist, enterprise='.1.3.6.1.4', agentAddr=None, genericTrap=6, specificTrap=0):
        """ Creates a Trap PDU object from a list of strings and integers
            along with a varBindList to make it a bit easier to build a Trap.
        """
        ent = rfc1155.ObjectID(stringval=enterprise)
        if not agentAddr:
            agentAddr = self.sock.getsockname()[0]
        agent = rfc1155.NetworkAddress(stringval=agentAddr)
        gTrap = rfc1157.GenericTrap(genericTrap)
        sTrap = rfc1155.Integer(specificTrap)
        ts = rfc1155.TimeTicks( self.getSysUptime() )

        pdu = rfc1157.TrapPDU(ent, agent, gTrap, sTrap, ts, varbindlist)
#        log.debug('v1.trap is %s' % pdu)
        return pdu

    def snmpGet(self, oid, remote, callback, community='public'):
        """ snmpGet issues an SNMP Get Request to remote for
            the object ID oid 
            remote is a tuple of (host, port)
            oid is a dotted string eg: .1.2.6.1.0.1.1.3.0
        """
        msg = self.createGetRequestMessage( oid, community )

        # add this message to the outbound queue as a tuple
        self.outbound.put( (msg, remote) )
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
        msg = self.createGetNextRequestMessage( varbindlist, community )

        # add this message to the outbound queue as a tuple
        self.outbound.put( (msg, remote) )
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
        pdu = rfc1157.GetNextRequestPDU( reqID, varBindList=varbindlist )
        msg = rfc1157.Message( community=community, data=pdu )

        # add this message to the outbound queue as a tuple
        self.outbound.put( (msg, remote) )
        # Add the callback to my dictionary with the requestID
        # as the key for later retrieval
        self.callbacks[int(msg.data.requestID)] = callback
        return msg.data.requestID

    def snmpTrap(self, remote, trapPDU, community='public'):
        """ Queue up a trap for sending
        """
        msg = self.createTrapMessage(trapPDU, community)

        self.outbound.put( (msg, remote) )

    def createSetRequestMessage(self, varBindList, community='public'):
        """ Creates a message object from a pdu and a
            community string.
        """

    def receiveData(self, data):
        """ This method should be called when data is received
            from a remote host.
        """

        # perform the action on the message by calling the
        # callback from my list of callbacks, passing it the
        # message and a reference to myself

        try:
            # Decode the data into a message
            msg = rfc1157.Message().decode(data)

            # Figure out what kind of PDU the message contains
            if isinstance(msg.data, rfc1157.RequestPDU):
#               if __debug__: log.debug('response to requestID: %d' % msg.data.requestID)
                self.callbacks[int(msg.data.requestID)](self, msg)

                # remove the callback from my list once it's done
                del self.callbacks[int(msg.data.requestID)]

            elif isinstance(msg.data, rfc1157.TrapPDU):
                if __debug__: log.debug('Detected an inbound Trap')
                self.trapCallback(self, msg)

            else:
                log.debug('Unknown message type')

        # log any errors in callback
        except Exception, e:
#            log.error('Exception in callback: %s: %s' % (self.callbacks[int(msg.data.requestID)].__name__, e) )
            log.error('Exception in receiveData: %s' % e )
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
        while 1:
            # send any pending outbound messages
            try:
                request = self.outbound.get(0)
                self.sock.sendto( request[0].encode(), request[1] )

            except Queue.Empty:
                if self.queueEmpty:
                    self.queueEmpty(self)
                pass

            # see if there's anything inbound
            try:
                (inlist, outlist, errlist) = select.select( [self.sock], [], [], self.timeout )
                if inlist:
                    data = self.sock.recv(8096)
                    self.receiveData( data )

            except:
                raise

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
