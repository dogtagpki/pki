from pkilib.common.exceptions import DirSrvException
from pkilib.common.Qe_class import QeHost
from os.path import exists
from pkilib.common.factory import PkiTools
from ipapython import ipautil
from ipapython import certdb
import os
import ConfigParser
import os.path
import pwd
import array
import tempfile
import grp
import subprocess



# Constants
DS_USER = 'nobody'
DS_GROUP = 'nobody'
DS_admin = 'admin'
DS_ROOTDN = 'CN=Directory Manager'

class DirSrv(object):
    """ 
    Setup/Remove Directory Server Instances used by CS subsystems.
    """
    def __init__(self, InstName, InstHost, InstSuffix, RootDNPwd=None, LdapPort=None, TLSPort=None, MultiHost=None):
        """ 
        Initalize DirSrv Object with given Instance_Name, InstHost, suffix, LdapPort, and TLSPort. 

        :param str InstName: Directory Server Instance Name
	:param str InstHost: Host on which Directory server should be setup
	:param str InstSuffix: Suffix required for setup
	:param str RootDNPwd: RootDN Password
	:param str LdapPort: Ldap Port to be used (optional)
	:param int TlsPort: TLSPort to be used for setup (optional)
	:param obj Multihost: Object from pytest multihost plugin (optional)

        """
        self.InstName = InstName
        self.DSInstHost = InstHost
        self.DSInstSuffix = InstSuffix
        self.DSLdapPort = LdapPort
        self.DSTLSPort = TLSPort
        self.DSRootDN = DS_ROOTDN
        self.DSRootDNPwd = RootDNPwd
        self.DSInstName = 'slapd-%s' % InstName
        self.DSRootDir = '/etc/dirsrv'
        self.DSInstPath = os.path.join(self.DSRootDir, self.DSInstName)
        self.MultiHost = MultiHost

    def __str__(self):
        return "%s.%s('%r')" % (self.__module__, self.__class__.__name__, self.__dict__)

    def ___repr__(self):
        return '%s(%s, %r)' % (self.__class__.__name__, self.__dict__)

    def create_config(self):
        """
	Creates the configuration file for setup-ds.pl to create Directory server Instance. 
	
	:param: None
        
	:return: File path containing config file.
        """
        config = ConfigParser.RawConfigParser()
        config.optionxform = str

        config.add_section('General')
        config.set('General', 'FullMachineName', self.DSInstHost)
        config.set('General', 'SuiteSpotUserID', DS_USER)
        config.set('General', 'SuiteSpotGroup', DS_GROUP)
        config.set('General', 'ConfigDirectoryAdminID', DS_admin)
        config.add_section('slapd')
        config.set('slapd', 'ServerIdentifier', self.InstName)
        config.set('slapd', 'ServerPort', self.DSLdapPort)
        config.set('slapd', 'Suffix', self.DSInstSuffix)
        config.set('slapd', 'RootDN', self.DSRootDN)
        config.set('slapd', 'RootDNPwd', self.DSRootDNPwd)
        (DScfgfile_fd, DScfg_file_path) = tempfile.mkstemp(suffix='cfg')

        os.close(DScfgfile_fd)
        with open(DScfg_file_path, "wb") as f:
            config.write(f)
        return DScfg_file_path

    def Setup_DSInstance(self, DSCfg_file):
        """
	Creates Directory server instance by running setup-ds.pl.
	if MultiHost parameter is passed to DirSrv Object then InstHost parameter contains
	the actual host on which setup-ds.pl is run else setup-ds.pl is run on localhost

	:param: Configuration File path 
	:return: True if seutp-ds.pl ran successfully else false 
	
	Todo: Should raise an DirSrvException
        """
        if isinstance(self.MultiHost, QeHost):
            self.MultiHost.transport.put_file(DSCfg_file, '/tmp/test.cfg')
            setup_args = ['setup-ds.pl', '--silent', '--file=/tmp/test.cfg', '--debug']
            try:
                output = self.MultiHost.run_command(setup_args, log_stdout=True,raiseonerr=True)
            except subprocess.CalledProcessError as E:
                return False
            else:
                os.remove(DSCfg_file)
                return True
        else:
            setup_args = ['setup-ds.pl', '--silent', '--file=%s' % DSCfg_file]
        try:
            stdin, stdout, return_code = PkiTools.execute(setup_args, raiseonerr=True)
        except ipautil.CalledProcessError as e:
            return False
        else:
            os.remove(DSCfg_file)
            return True

    def Remove_DSInstance(self, InstName=None):
        """ 
	Removes Directory server Instance 

	:param str InstName: Instance Name
        :return bool: Returns True is successfull else Returns False
	
	Todo: Should raise an DirSrvException
        """
        if InstName is None:
            InstName = self.DSInstName
        remove_args = ['remove-ds.pl', '-i', InstName, '-d']
        if isinstance(self.MultiHost, QeHost):
            try:
                output = self.MultiHost.run_command(remove_args, log_stdout=True,raiseonerr=True)
            except subprocess.CalledProcessError as E:
                return False
            else:
                return True
        else:
            try:
                stdin, stdout, return_code = ipautil.run(remove_args, raiseonerr=True)
            except ipautil.CalledProcessError as e:
                return False
            else:
                return True

    def CreateSelfSignedCerts(self):
        """ 
        Creates NSS DB on the Directory Instance Directory and creates self signed certificates using certutil command. 

	:param: None
	:return bool:  True if certs are created else Raises DirSrvException.
            
	Note: This method uses certdb function from ipapython to create NSS DB directory
        """
        DSCertDBOjb = certdb.NSSDatabase(nssdir=self.DSInstPath)
        DSNSSPassPhrase = 'Secret123'
        (pwdfile_fd, pwd_file_path) = tempfile.mkstemp()
        os.write(pwdfile_fd, DSNSSPassPhrase)
        os.close(pwdfile_fd)

        #setup NSS DB with the password created
        DSCertDBOjb.create_db(pwd_file_path)
        #since there is no exception handling , we need to verify
        #if the nssdb is created properly, we check if cert8.db,
        #secmod.db and key3.db exists
        nss_db_file = ['cert8.db', 'key3.db', 'secmod.db']
        for files in nss_db_file:
            if not exists(os.path.join(self.DSInstPath, files)):
                raise DirSrvException('Could not setup NSS DB on %s' % self.DSInstPath)

        # create Noise File
        noise = array.array('B', os.urandom(128))
        (noise_fd, noise_name) = tempfile.mkstemp()
        os.write(noise_fd, noise)
        os.close(noise_fd)
        ca_args = ["-f", pwd_file_path,
                "-S", 
                "-n", "Example CA",
                "-s", "CN=Example CA,O=Example,L=Raleigh,C=US",
                "-t", "CT,,",
                "-x",
                "-z", noise_name]


        stdin, stdout, return_code = DSCertDBOjb.run_certutil(ca_args)
        if return_code != 0:
            raise DirSrvException('Could not create Self signed CA Cert')

        server_dn = "CN=%s" % (self.DSInstHost)

        server_args = ["-f", pwd_file_path,
                "-S",
                "-n", "Server-Cert",
                "-s", server_dn,
                "-c", "Example CA",
                "-t", "u,u,u",
                "-v", "720",
                "-m", "1001",
                "-z", noise_name]
        
        stdin, stdout, return_code = DSCertDBOjb.run_certutil(server_args)
        if return_code != 0: 
            raise DirSrvException('Could not create Server-Cert')

        os.remove(pwd_file_path)
        os.remove(noise_name)

        ##write password to pin.txt
        pin_file = os.path.join(self.DSInstPath, 'pin.txt')
        pin_fd = open(pin_file, "w")
        pin_fd.write('Internal (Software) Token:%s' % DSNSSPassPhrase)
        pin_fd.close()

        #all these files are to be owned by #dirsrv a/c
        DSUID = pwd.getpwnam(DS_USER)
        DSGID = grp.getgrnam(DS_GROUP)
        for files in nss_db_file:
            os.chown((os.path.join(self.DSInstPath, files)), DSUID.pw_uid, DSGID.gr_gid)
        os.chown(pin_file, DSUID.pw_uid, DSGID.gr_gid)
        os.chmod(pin_file, 0400)

        return True
