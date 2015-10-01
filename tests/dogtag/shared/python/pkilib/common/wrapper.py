from pkilib.common.exceptions import DirSrvException
from pkilib.common.factory import PkiTools
from pkilib.common.libdirsrv2 import DirSrv
from ipapython import ipautil
from os.path import exists
import os.path
import subprocess
import socket


class W_DirSrv(object):
    """ 
    This is a wrapper class for DirSrv object 
    Validates all the inputs sent to DirSrv object.
    Chooses Ldap and SSL Ports sanely Validates the inputs 
    and In cases uses certain default values in 
    cases not all options are provided.
    """
    def __init__(self):

        self.DSUsedPorts = {}
        self.DirSrvInfo = {}
        self.DirSrvInst = None

    def _set_options(self):

        if self.DSInstHost is None:
            self.DSInstHost = socket.gethostname()

        if self.DSRootDNPwd is None:
            self.DSRootDNPwd = 'Secret123'

        if self.DSInstSuffix is None:
            self.DSInstSuffix = "o=%s" % self.DSIntName

        try:
            self.DSLdapPort, self.DSTLSPort = self._set_ports(self.DSLdapPort, self.DSTLSPort)
        except IndexError as err:
            return ("No More ports available", 1)
        else:
            self.DSUsedPorts[self.DSIntName]=(self.DSLdapPort, self.DSTLSPort)

        output, process_ret = self._bind_to_selinux([self.DSLdapPort, self.DSTLSPort])
        if process_ret != 0:
            raise DirSrvException("Unable to bind ports to ldap_port_t, Error: ",output)
        else:
            try:
                self._validate_options()
            except DirSrvException as err:
                return err.msg, err.rval
            else:
                return ("Success", 0)

    def _set_ports(self, u_port, e_port):

        """
        Idea behind this is when a directory server instance needs
        to be created we need ports for ldap and ssl ports.
        1. check if LdapPort and SSLPort is given
            1.1 If given, verify if the ports are available(not used)
                1.1.1. Bind that port to ldap_port_t using semanage command
                1.1.2. Use the ports and add it to the self.UsedPorts list
            1.2 else raise exception
        2. If LdapPort and SSLPort is not given.
            2.1 Check if the ports are available(not used)
            2.1.1. Bind the port to ldap_port_t using semanage command
            2.1.2. Use the ports and add it to self.UsedPorts list
        """
        DSPorts = [30389, 31389, 32389, 33389, 34389, 35389, 36389, 37389, 38389, 39389]
        TLSPorts = [30636, 31636, 32636, 33636, 34636, 35636, 36636, 37636, 38636, 39636]

        if u_port is None and e_port is None:
            for ldap_port, ldaps_port in zip(DSPorts, TLSPorts):
                if (self._check_port(ldap_port) or self._check_port(ldaps_port)):
                    pass
                else:
                    return ldap_port, ldaps_port
        else:
            a = []
            for ports in self.DSUsedPorts.values():
                a.append(ports)
            
            b = []
            for l_port, s_port in zip(DSPorts, TLSPorts):
                b.append((l_port,s_port))

            if (len(set(a)) > len(set(b))):
                available_ports = set(a) - set(b)
            else:
                available_ports = set(b) - set(a)
            print("available_ports =", available_ports)
            sorted_available_ports = sorted(available_ports)
            return sorted_available_ports[0]

    def _check_port(self, port):
        """ 
        Verify if the port given is available. 
        Returns True if port is already in use else returns False  
        """
        return ipautil.host_port_open(None, port)

    def _bind_to_selinux(self, ldap_ports):
        """ Use semanage to bind ldap and ldaps ports to ldap_port_t  """
        for port in ldap_ports: 
            semanage_args = ['semanage', 'port', '-a', '-t', 'ldap_port_t', '-p', 'tcp', str(port)] 
            try:
                stdout, stderr, process_ret = PkiTools.Execute(semanage_args)
            except subprocess.CalledProcessError:
                return ("Error", 1)
            else:
                if process_ret == 1:
                    return stdout, 0
                elif process_ret != 0:
                    return stderr, process_ret
                else:
                    return stdout, process_ret

    def _validate_options(self):
        if exists(os.path.join('/etc/dirsrv/', 'slapd-%s' % self.DSIntName)):
            raise DirSrvException('%s Instance already Exists' % self.DSIntName)
        else:
            return True

    def _CreateInstance(self, InstName, InstHost=None, InstSuffix=None, RootDNPwd=None, LdapPort=None, TLSPort=None):

        self.DSIntName = InstName
        self.DSInstHost = InstHost
        self.DSInstSuffix = None
        self.DSRootDNPwd = RootDNPwd
        self.DSLdapPort = LdapPort
        self.DSTLSPort = TLSPort

        result, return_code =  self._set_options()
        if return_code == 0:
            self.DirSrvInst = DirSrv(self.DSIntName, self.DSInstHost, 
                    self.DSInstSuffix, self.DSRootDNPwd, self.DSLdapPort, 
                    self.DSTLSPort)
            cfg_file = self.DirSrvInst._create_config()
            result = self.DirSrvInst._Setup_DSInstance(cfg_file)
            self.DirSrvInfo[self.DSIntName] = self.DirSrvInst.__dict__
            return result
        else:
            return result, return_code

    def _RemoveInstance(self, InstName):
        ret = self.DirSrvInfo[InstName]
        if ret['InstName'] == InstName:
            DSInstName = ret['DSInstName']
            result = self.DirSrvInst._Remove_DSInstance(DSInstName)
            if result:
                del self.DSUsedPorts[InstName]
                return True
            else:
                return False
        else:
            return False

