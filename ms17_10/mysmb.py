import os
import random
import sys
from struct import pack

from impacket import nt_errors, smb


def getNTStatus(self):
    return (self['ErrorCode'] << 16) | (self['_reserved'] << 8) | self['ErrorClass']


setattr(smb.NewSMBPacket, "getNTStatus", getNTStatus)

def _put_trans_data(transCmd, parameters, data, noPad=False):
    # have to init offset before calling len()
    transCmd['Parameters']['ParameterOffset'] = 0
    transCmd['Parameters']['DataOffset'] = 0

    # SMB header: 32 bytes
    # WordCount: 1 bytes
    # ByteCount: 2 bytes
    # Note: Setup length is included when len(param) is called
    offset = 32 + 1 + len(transCmd['Parameters']) + 2

    transData = ''
    if len(parameters):
        padLen = 0 if noPad else (4 - offset % 4) % 4
        transCmd['Parameters']['ParameterOffset'] = offset + padLen
        transData = ('\x00' * padLen) + parameters
        offset += padLen + len(parameters)

    if len(data):
        padLen = 0 if noPad else (4 - offset % 4) % 4
        transCmd['Parameters']['DataOffset'] = offset + padLen
        transData += ('\x00' * padLen) + data

    transCmd['Data'] = transData


origin_NewSMBPacket_addCommand = getattr(smb.NewSMBPacket, "addCommand")
login_MaxBufferSize = 61440


def NewSMBPacket_addCommand_hook_login(self, command):
    # restore NewSMBPacket.addCommand
    setattr(smb.NewSMBPacket, "addCommand", origin_NewSMBPacket_addCommand)

    if isinstance(command['Parameters'], smb.SMBSessionSetupAndX_Extended_Parameters):
        command['Parameters']['MaxBufferSize'] = login_MaxBufferSize
    elif isinstance(command['Parameters'], smb.SMBSessionSetupAndX_Parameters):
        command['Parameters']['MaxBuffer'] = login_MaxBufferSize

    # call original one
    origin_NewSMBPacket_addCommand(self, command)


def _setup_login_packet_hook(maxBufferSize):
    # setup hook for next NewSMBPacket.addCommand if maxBufferSize is not None
    if maxBufferSize is not None:
        global login_MaxBufferSize
        login_MaxBufferSize = maxBufferSize
        setattr(smb.NewSMBPacket, "addCommand", NewSMBPacket_addCommand_hook_login)


class MYSMB(smb.SMB):
    # NEEDED
    def __init__(self, remote_host, remote_port, use_ntlmv2=True, timeout=8):
        self.__use_ntlmv2 = use_ntlmv2
        self._default_tid = 0
        self._pid = os.getpid() & 0xffff
        self._last_mid = random.randint(1000, 20000)
        if 0x4000 <= self._last_mid <= 0x4110:
            self._last_mid += 0x120
        self._pkt_flags2 = 0
        self._last_tid = 0  # last tid from connect_tree()
        self._last_fid = 0  # last fid from nt_create_andx()
        self._smbConn = None
        try:
            smb.SMB.__init__(self, remote_host, remote_host, sess_port=remote_port, timeout=timeout)
        except Exception as e:
            print('[-] ' + str(e))
            sys.exit()

    # NEEDED
    def check_ms17_010(self):
        TRANS_PEEK_NMPIPE = 0x23
        recvPkt = self.send_trans(pack('<H', TRANS_PEEK_NMPIPE), maxParameterCount=0xffff, maxDataCount=0x800)
        status = recvPkt.getNTStatus()
        if status == 0xC0000205:  # STATUS_INSUFF_SERVER_RESOURCES
            print('[!] The target is vulnerable')
            return True
        else:
            print('[-] The target is not vulnerable')
            return False

    def next_mid(self):
        self._last_mid += random.randint(1, 20)
        if 0x4000 <= self._last_mid <= 0x4110:
            self._last_mid += 0x120
        return self._last_mid

    # to use any login method, SMB must not be used from multiple thread
    def login(self, user, password, domain='', lmhash='', nthash='', ntlm_fallback=True, maxBufferSize=None):
        _setup_login_packet_hook(maxBufferSize)
        smb.SMB.login(self, user, password, domain, lmhash, nthash)

    # NEEDED
    def login_or_fail(self, username, password, maxBufferSize=None):
        try:
            self.login(username, password, maxBufferSize=maxBufferSize)
        except smb.SessionError as e:
            print('[-] Login failed: ' + nt_errors.ERROR_MESSAGES[e.error_code][0])
            sys.exit()

    # NEEDED
    def set_default_tid(self, tid):
        self._default_tid = tid

    def create_smb_packet(self, smbReq, mid=None, pid=None, tid=None):
        if mid is None:
            mid = self.next_mid()

        # Create a new SMB packet
        pkt = smb.NewSMBPacket()
        
        # Add the SMB request command to the packet
        pkt.addCommand(smbReq)
        
        # Set various fields in the SMB packet
        pkt['Tid'] = self._default_tid if tid is None else tid
        pkt['Uid'] = self._uid
        pkt['Pid'] = self._pid if pid is None else pid
        pkt['Mid'] = mid
        
        # Get flags and set them in the packet
        flags1, flags2 = self.get_flags()
        pkt['Flags1'] = flags1
        pkt['Flags2'] = self._pkt_flags2 if self._pkt_flags2 != 0 else flags2

        # If signatures are enabled, apply the security signature to the packet
        if self._SignatureEnabled:
            pkt['Flags2'] |= smb.SMB.FLAGS2_SMB_SECURITY_SIGNATURE
            self.signSMB(pkt, self._SigningSessionKey, self._SigningChallengeResponse)

        # Convert the packet to raw bytes, assuming `getData()` or similar exists
        raw_data = pkt.getData()  # This method should return the raw byte data of the packet

        # Return the SMB packet with length header (2 bytes for length)
        return b'\x00' * 2 + pack('>H', len(raw_data)) + raw_data


    def send_raw(self, data):
        self.get_socket().send(data)

    def create_trans_packet(self, setup, param='', data='', mid=None, maxSetupCount=None, totalParameterCount=None,
                            totalDataCount=None, maxParameterCount=None, maxDataCount=None, pid=None, tid=None,
                            noPad=False):
        if maxSetupCount is None:
            maxSetupCount = len(setup)
        if totalParameterCount is None:
            totalParameterCount = len(param)
        if totalDataCount is None:
            totalDataCount = len(data)
        if maxParameterCount is None:
            maxParameterCount = totalParameterCount
        if maxDataCount is None:
            maxDataCount = totalDataCount
        transCmd = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION)
        transCmd['Parameters'] = smb.SMBTransaction_Parameters()
        transCmd['Parameters']['TotalParameterCount'] = totalParameterCount
        transCmd['Parameters']['TotalDataCount'] = totalDataCount
        transCmd['Parameters']['MaxParameterCount'] = maxParameterCount
        transCmd['Parameters']['MaxDataCount'] = maxDataCount
        transCmd['Parameters']['MaxSetupCount'] = maxSetupCount
        transCmd['Parameters']['Flags'] = 0
        transCmd['Parameters']['Timeout'] = 0xffffffff
        transCmd['Parameters']['ParameterCount'] = len(param)
        transCmd['Parameters']['DataCount'] = len(data)
        transCmd['Parameters']['Setup'] = setup
        _put_trans_data(transCmd, param, data, noPad)
        return self.create_smb_packet(transCmd, mid, pid, tid)

    def send_trans(self, setup, param='', data='', mid=None, maxSetupCount=None, totalParameterCount=None,
                   totalDataCount=None, maxParameterCount=None, maxDataCount=None, pid=None, tid=None, noPad=False):
        self.send_raw(
                    self.create_trans_packet(setup, param, data, mid, maxSetupCount, totalParameterCount,
                                             totalDataCount,
                                             maxParameterCount, maxDataCount, pid, tid, noPad))
        return self.recvSMB()


