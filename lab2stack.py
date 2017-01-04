#!/usr/bin/python
# -*- coding: utf-8 -*-
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import task
from twisted.internet import reactor
from zope.interface.declarations import implements
from twisted.internet.interfaces import ITransport, \
    IStreamServerEndpoint
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import STRING, \
    UINT4, OPTIONAL, BOOL1, DEFAULT_VALUE, LIST
from playground.network.common.Protocol import MessageStorage, \
    StackingTransport, StackingProtocolMixin, StackingFactoryMixin
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from playground.crypto import X509Certificate
import random
from time import sleep
import os.path
import time
import CertFactory

riplog = ''


def riplogger(msg):
    global riplog  # Needed to modify global copy of globvar
    riplog = msg


def intToNonce(i):
    h = hex(i)
    h = h[2:]  # remove 0x
    if h[-1] == 'L':
        h = h[:-1]  # remove "L"
    return h


def print_riplogger():
    print riplog


def loadCert(filepath):
    with open(filepath, 'r') as f:
        certBytes = f.read()
    return (X509Certificate.loadPEM(certBytes), certBytes)


def returnCert(bytes):
    return X509Certificate.loadPEM(bytes)


def returnKey(bytes):
    rsaKey = RSA.importKey(bytes)
    return PKCS1_v1_5.new(rsaKey)


def loadKey(filepath):
    with open(filepath, 'r') as f:
        rawKey = f.read()
    rsaKey = RSA.importKey(rawKey)
    return PKCS1_v1_5.new(rsaKey)


def trunc_at(s, d, n=3):
    return d.join(s.split(d)[:n])


def chunkstring(string, length):
    return (string[0 + i:length + i] for i in range(0, len(string),
                                                    length))


class RIPMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = 'RIP.RIPMessage'
    MESSAGE_VERSION = '1.1'
    BODY = [
        ('sequence_number', UINT4),
        ('acknowledgement_number', UINT4, DEFAULT_VALUE(0)),
        ('signature', STRING, DEFAULT_VALUE('')),
        ('certificate', LIST(STRING), OPTIONAL),
        ('sessionID', STRING, OPTIONAL),
        ('acknowledgement_flag', BOOL1, DEFAULT_VALUE(False)),
        ('close_flag', BOOL1, DEFAULT_VALUE(False)),
        ('sequence_number_notification_flag', BOOL1,
         DEFAULT_VALUE(False)),
        ('reset_flag', BOOL1, DEFAULT_VALUE(False)),
        ('data', STRING, DEFAULT_VALUE('')),
        ('OPTIONS', LIST(STRING), OPTIONAL),
    ]


class State:
    def handleInput(self, message, protocol):
        raise NotImplementedError('Input not handled!')

    def Authenticator(self, certlist, protocol):
        protocol.peercert2 = X509Certificate.loadPEM(certlist[3])
        protocol.peercert1 = X509Certificate.loadPEM(certlist[2])
        protocol.RootCert = X509Certificate.loadPEM(protocol.RootBytes)
        if protocol.peercert2.getIssuer() \
                != protocol.RootCert.getSubject():
            return False
        rootPkBytes = protocol.RootCert.getPublicKeyBlob()
        rootPK = RSA.importKey(rootPkBytes)
        rootVerifier = PKCS1_v1_5.new(rootPK)
        bytesToVerify = \
            protocol.peercert2.getPemEncodedCertWithoutSignatureBlob()
        hasher = SHA256.new()
        hasher.update(bytesToVerify)
        sign3 = protocol.peercert2.getSignatureBlob()
        if not rootVerifier.verify(hasher, sign3):
            return False
        else:
            if protocol.peercert1.getIssuer() \
                    != protocol.peercert2.getSubject():
                return False
            CAPkBytes = protocol.peercert2.getPublicKeyBlob()
            peerCAPublicKey = RSA.importKey(CAPkBytes)
            peerCAVerifier = PKCS1_v1_5.new(peerCAPublicKey)
            bytesToVerify1 = \
                protocol.peercert1.getPemEncodedCertWithoutSignatureBlob()
            hasher1 = SHA256.new()
            hasher1.update(bytesToVerify1)
            if peerCAVerifier.verify(hasher1,
                                     protocol.peercert1.getSignatureBlob()):
                return True
            else:
                return False

    def SignData(self, data, protocol):
        hasher = SHA256.new()
        hasher.update(str(data))
        return protocol.rsaSigner.sign(hasher)

    def VerifySignedData(self, message, certificate):

        signature = message.signature
        message.signature = ''
        cert = returnCert(certificate)
        peerPublicKeyBlob = cert.getPublicKeyBlob()
        peerPublicKey = RSA.importKey(peerPublicKeyBlob)
        rsaVerifier = PKCS1_v1_5.new(peerPublicKey)
        hasher = SHA256.new()
        hasher.update(message.__serialize__())
        if not rsaVerifier.verify(hasher, signature):
            return False
        else:
            return True

    def RandomNumber(self):
        return int(random.uniform(10000, 99999))


class Listen(State):
    def handleInput(self, message, protocol):
        if message.sequence_number_notification_flag is True \
                and self.VerifySignedData(message, message.certificate[2]) \
                        is True:
            if self.Authenticator(message.certificate, protocol) \
                    is not True:
                return 1
            protocol.RemoveFromBuffer(message)
            protocol.lastsequencenumber = self.RandomNumber()
            protocol.lastacknumber = message.sequence_number \
                                     + len(message.data) + 1
            protocol.peercert1 = message.certificate[2]
            protocol.peercert2 = message.certificate[3]
            message.acknowledgement_number = protocol.lastacknumber
            message.sequence_number = protocol.lastsequencenumber
            message.sequence_number_notification_flag = True
            message.acknowledgement_flag = True
            protocol.nonce = self.RandomNumber()
            message.sessionID = str(int(message.certificate[0], 16)) \
                                + str(protocol.nonce)
            message.certificate = ['', intToNonce(protocol.nonce),
                                   protocol.CertBytes, protocol.CABytes]
            message.signature = ''
            message.signature = self.SignData(message, protocol)
            protocol.transport.write(message.__serialize__())
            protocol.AddToBuffer(message)
            return 3
        else:
            protocol.transport.loseConnection()
            return 1


class SNNSENT(State):
    def handleInput(self, message, protocol):
        if message.sequence_number_notification_flag is True \
                and message.acknowledgement_flag is True \
                and self.VerifySignedData(message, message.certificate[2]) \
                        is True:
            if self.Authenticator(message.certificate, protocol) \
                    is not True:
                return 2
            protocol.RemoveFromBuffer(message)
            protocol.lastsequencenumber = message.acknowledgement_number
            protocol.lastacknumber = message.sequence_number \
                                     + len(message.data) + 1
            protocol.peercert1 = message.certificate[2]
            protocol.peercert2 = message.certificate[3]
            message.acknowledgement_number = protocol.lastacknumber
            message.sequence_number = protocol.lastsequencenumber
            message.sequence_number_notification_flag = False
            message.acknowledgement_flag = True
            message.certificate = ['', '', '', '']
            message.signature = ''
            message.signature = self.SignData(message, protocol)
            protocol.transport.write(message.__serialize__())
            protocol.AddToBuffer(message)
            protocol.RemoveFromBuffer(message)
            protocol.flushbuffer()
            return 4
        else:
            protocol.transport.loseConnection()
            return 2


class SNNACKSENT(State):
    def handleInput(self, message, protocol):
        if message.acknowledgement_flag is True \
                and self.VerifySignedData(message, protocol.peercert1) \
                        is True:
            protocol.RemoveFromBuffer(message)

            # protocol.lastsequencenumber = message.acknowledgement_number
            # protocol.lastacknumber = message.sequence_number + len(message.data)
            # message.sequence_number = protocol.lastsequencenumber
            # message.acknowledgement_number = protocol.lastacknumber

            protocol.flushbuffer()
            protocol.Retransmit.start(3.0)
            return 4
        else:
            protocol.transport.loseConnection()
            return 3


class Closed_Client(State):
    def handleInput(self, message, protocol):
        message.sequence_number = self.RandomNumber()
        message.acknowledgement_number = 0
        protocol.lastsequencenumber = message.sequence_number
        message.sequence_number_notification_flag = True
        protocol.nonce = self.RandomNumber()
        message.certificate = [str(intToNonce(protocol.nonce)), '',
                               protocol.CertBytes, protocol.CABytes]
        message.signature = ''
        message.signature = self.SignData(message, protocol)
        protocol.transport.write(message.__serialize__())
        protocol.AddToBuffer(message)
        return 2


class Established(State):
    def handleInput(self, message, protocol):
        protocol.RemoveFromBuffer(message)
        if protocol.factory.role == 'client' and protocol.clientestflag \
                == 0:
            protocol.Retransmit.start(3.0)
            protocol.lastmsgbytes = len(message.data)
            message.sequence_number = protocol.lastsequencenumber
            message.acknowledgement_number = protocol.lastacknumber
            message.certificate = ['', '', '', '']
            message.signature = ''
            message.signature = self.SignData(message, protocol)
            protocol.transport.write(message.__serialize__())
            protocol.AddToBuffer(message)
            protocol.clientestflag = 1
        else:
            message.sequence_number = protocol.lastsequencenumber
            message.acknowledgement_number = protocol.lastacknumber + 1
            message.acknowledgement_flag = True
            message.certificate = ['', '', '', '']
            message.signature = ''
            message.signature = self.SignData(message, protocol)
            protocol.transport.write(message.__serialize__())
            protocol.AddToBuffer(message)


class CloseWait(State):
    def handleInput(self, message, protocol):
        message.close_flag = True
        message.acknowledgement_flag = False
        message.sequence_number = protocol.lastsequencenumber
        protocol.transport.write(message.__serialize__())


class CloseRcvd(State):
    def handleInput(self, message, protocol):
        message.sequence_number = protocol.lastsequencenumber
        message.acknowledgement_flag = True
        message.close_flag = True
        protocol.rcvdmsgbuffer = {}
        protocol.transport.write(message.__serialize__())
        if protocol.factory.role == 'server':
            protocol.Retransmit.stop()
            protocol.__init__(protocol.factory)
            protocol.higherProtocol().connectionLost(protocol.higherTransport)
            protocol.CurrentState = 1
            return 1
        if protocol.factory.role == 'client':
            protocol.higherProtocol().connectionLost(protocol.higherTransport)  # reactor.stop()....


class Closed(State):
    def handleInput(self, message, protocol):
        if protocol.factory.role == 'server':
            protocol.Retransmit.stop()
            protocol.__init__(protocol.factory)
            protocol.CurrentState = 1
            protocol.rcvdmsgbuffer = {}
            protocol.higherProtocol().connectionLost(protocol.higherTransport)
            return 1
        if protocol.factory.role == 'client':
            protocol.Retransmit.stop()
            protocol.rcvdmsgbuffer = {}
            protocol.higherProtocol().connectionLost(protocol.higherTransport)


            # reactor.stop()


class RIPTransport(StackingTransport):
    def __init__(self, lowerTransport, protocol):
        StackingTransport.__init__(self, lowerTransport)
        self.protocol = protocol

    def write(self, data):
        for data in chunkstring(data, 16384):
            message = RIPMessage()
            message.data = data
            self.protocol.state[self.protocol.CurrentState]().handleInput(message,
                                                                          self.protocol)

    def loseConnection(self):
        if self.protocol.CurrentState == 8:
            self.lowerTransport().loseConnection
        message = RIPMessage()
        self.protocol.CurrentState = 5
        self.CurrentState = \
            self.protocol.state[self.protocol.CurrentState]().handleInput(message,
                                                                          self.protocol)


class RIP(StackingProtocolMixin, Protocol):
    state = [
        Closed_Client,
        Listen,
        SNNSENT,
        SNNACKSENT,
        Established,
        CloseWait,
        CloseRcvd,
        Closed,
    ]

    def __init__(self, Factory):
        self.storage = MessageStorage()
        self.factory = Factory
        self.CurrentState = 0
        self.estflag = 0
        self.clientestflag = 0
        self.lastsequencenumber = 0
        self.lastacknumber = 0
        self.lastmsgbytes = 0
        self.nonce = 0
        self.RootBytes = None
        self.CertBytes = None
        self.CABytes = None
        self.Cert = None
        self.CACert = None
        self.RootCert = None
        self.rsaSigner = None
        self.TrustedPeers = {}
        self.peercert1 = None
        self.peercert2 = None
        self.higherTransport = None
        self.messagebuffer = None
        self.timer = None
        self.sentmsgbuffer = {}
        self.rcvdmsgbuffer = {}
        self.Retransmit = task.LoopingCall(self.Retransmitter)

    def AddToBuffer(self, msg):
        msgtime = int(time.time())
        self.sentmsgbuffer = {msgtime: [msg, 0]}

    def Retransmitter(self):
        if len(self.sentmsgbuffer) > 0:
            for key in sorted(self.sentmsgbuffer.iterkeys()):
                msg = self.sentmsgbuffer[key][0]
                attempt = self.sentmsgbuffer[key][1]
                if attempt < 3:
                    if int(time.time()) - key >= 6:
                        self.transport.write(msg.__serialize__())
                        self.sentmsgbuffer[key][1] = attempt + 1

    def RemoveFromBuffer(self, msg):
        index = msg.acknowledgement_number - len(msg.data) - 1
        for (key, value) in self.sentmsgbuffer.items():
            if value[0].acknowledgement_number == index:
                self.sentmsgbuffer.pop(key)

    def flushbuffer(self):
        self.sentmsgbuffer = {}
        self.rcvdmsgbuffer = {}

    def reset(self):
        self.__init__(self.name, self.author)

    def send(self, message):
        self.transport.write(message.__serialize__())

    def connectionMade(self):
        addr = str(self.transport.getHost()).split(':')[0]
        Certs = CertFactory.getCertsForAddr(addr)
        self.RootBytes = CertFactory.getRootCert()
        self.CertBytes = Certs[0]
        self.CABytes = Certs[1]
        self.Cert = returnCert(self.CertBytes)
        self.CACert = returnCert(self.CABytes)
        self.RootCert = returnCert(self.RootBytes)
        self.rsaSigner = \
            returnKey(CertFactory.getPrivateKeyForAddr(addr))
        if self.factory.role == 'client':
            self.CurrentState = 0
            self.CurrentState = \
                self.state[self.CurrentState]().handleInput(RIPMessage(),
                                                            self)
        else:
            self.CurrentState = 1

    def createHigherTransport(self):
        self.higherTransport = RIPTransport(self.transport, self)
        self.makeHigherConnection(self.higherTransport)

    def inbuffer(self, number):
        if len(self.rcvdmsgbuffer) > 0:
            for (key, value) in self.rcvdmsgbuffer.items():
                if key == number:
                    return True
                else:
                    return False

    def flushrcvdmsgbuffer(self):
        self.rcvdmsgbuffer = {}

    def dataReceived(self, data):
        self.storage.update(data)
        for msg in self.storage.iterateMessages():
            if self.CurrentState >= 4:
                if self.estflag == 0 and self.factory.role == 'server':
                    self.createHigherTransport()
                    self.estflag = 1
                if msg.close_flag is True and msg.acknowledgement_flag \
                        is True:
                    self.CurrentState = 7
                    self.state[self.CurrentState]().handleInput(msg,
                                                                self)
                if msg.close_flag is True:
                    self.CurrentState = 6
                    self.state[self.CurrentState]().handleInput(msg,
                                                                self)
                if not self.inbuffer(msg.sequence_number):
                    self.rcvdmsgbuffer[msg.sequence_number] = msg
                    if self.higherProtocol():
                        if self.VerifySignedData(msg, self.peercert1) is True:
                            self.lastacknumber = msg.sequence_number \
                                             + len(msg.data) + 1
                            self.lastsequencenumber = \
                            msg.acknowledgement_number
                            if len(self.rcvdmsgbuffer) < 50:
                                self.higherProtocol().dataReceived(msg.data)
                                self.flushrcvdmsgbuffer()
            elif self.CurrentState < 4:
                self.CurrentState = \
                    self.state[self.CurrentState]().handleInput(msg,
                                                                self)
                if self.CurrentState == 4 and self.factory.role \
                        == 'client':
                    self.createHigherTransport()


class RIPClientFactory(StackingFactoryMixin, Factory):
    protocol = RIP
    role = 'client'

    def buildProtocol(self, addr):
        return RIP(self)


class RIPServerFactory(StackingFactoryMixin, Factory):
    protocol = RIP
    role = 'server'

    def buildProtocol(self, addr):
        return RIP(self)


ConnectFactory = RIPClientFactory
ListenFactory = RIPServerFactory

