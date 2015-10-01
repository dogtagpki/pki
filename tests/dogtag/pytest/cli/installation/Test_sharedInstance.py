from pkilib.common.libdirsrv2 import DirSrv
from pkilib.common.wrapper import W_DirSrv
from pkilib.common.factory import PkiTools
import ConfigParser
import tempfile
import os
import shlex
import time
import socket
import pytest

@pytest.fixture(scope='function')
def TempFile(request):
    (tmp_cfg_fd, tmp_cfg_file_path) = tempfile.mkstemp()
    os.close(tmp_cfg_fd)
    def RemoveTempFile():
        print("Removing %r" %(tmp_cfg_file_path))
        os.remove(tmp_cfg_file_path)
    request.addfinalizer(RemoveTempFile)
    return tmp_cfg_file_path

@pytest.fixture(scope='function')
def DSInstance(InstanceName):
    a = W_DirSrv()
    a._CreateInstance(InstanceName)
    ldap_port = a.__dict__['DSLdapPort']
    #def teardown_DirSrvInstance():
    #    print("Removing Instance %s" % (DSInstance))
    #    a._RemoveInstance(request.param)
    #request.addfinalizer(teardown_DirSrvInstance)
    return ldap_port

class TestSharedTomcat(object):        
    """ Install subsystems sharing same tomcat and Directory Server Instances """
    def test_InstallCA(self, TempFile):
        """ Install CA with it's own tomcat instance to be shared with other subsystems """
        ldap_port = DSInstance('FoobarCA')
        caconfig = ConfigParser.RawConfigParser()
        caconfig.optionxform = str
        caconfig.set("DEFAULT", "pki_instance_name", 'Foobar1')
        caconfig.set("DEFAULT", "pki_https_port", 8443)
        caconfig.set("DEFAULT", "pki_http_port", 8080)
        caconfig.set("DEFAULT", "pki_token_password", 'Secret123')
        caconfig.set("DEFAULT", "pki_admin_password", 'Secret123')
        caconfig.set("DEFAULT", "pki_hostname", 'pki3.example.org')
        caconfig.set("DEFAULT", "pki_security_domain_name", "Example Org")
        caconfig.set("DEFAULT", "pki_security_domain_password", 'Secret123')
        caconfig.set("DEFAULT", "pki_client_dir", "/opt/Foobar1")
        caconfig.set("DEFAULT", "pki_client_pkcs12_password", "Secret123")
        caconfig.set("DEFAULT", "pki_backup_keys", "True")
        caconfig.set("DEFAULT", "pki_backup_password", "Secret123")
        caconfig.add_section('Tomcat')
        caconfig.set("Tomcat", "pki_ajp_port", "8009")
        caconfig.set("Tomcat", "pki_tomcat_server", "8005")
        caconfig.add_section("CA")
        caconfig.set("CA", "pki_import_admin_cert", "False")
        caconfig.set("CA", "pki_ds_hostname", "localhost")
        caconfig.set("CA", "pki_ds_ldap_port", ldap_port)
        caconfig.set("CA", "pki_ds_password", "Secret123")

        with open(TempFile, "wb") as f:
            caconfig.write(f)

        cmd = "pkispawn -s CA -f %s -vv" % (TempFile)
        args = shlex.split(cmd)
        stdout, stderr, return_code = PkiTools.Execute(args)
        assert return_code == 0
        time.sleep(5)

    def test_InstallKRA(self, TempFile):
        """ Install KRA sharing Tomcat Instance of CA """
        ldap_port = DSInstance('FoobarKRA')
        caconfig = ConfigParser.RawConfigParser()
        caconfig.optionxform = str
        caconfig.set("DEFAULT", "pki_instance_name", 'Foobar1')
        caconfig.set("DEFAULT", "pki_https_port", 8443)
        caconfig.set("DEFAULT", "pki_http_port", 8080)
        caconfig.set("DEFAULT", "pki_token_password", 'Secret123')
        caconfig.set("DEFAULT", "pki_admin_password", 'Secret123')
        caconfig.set("DEFAULT", "pki_security_domain_hostname", 'pki3.example.org')
        caconfig.set("DEFAULT", "pki_security_domain_https_port", "8443")
        caconfig.set("DEFAULT", "pki_security_domain_user", "caadmin")
        caconfig.set("DEFAULT", "pki_security_domain_password", "Secret123")
        caconfig.set("DEFAULT", "pki_client_dir", "/opt/Foobar1")
        caconfig.set("DEFAULT", "pki_client_pkcs12_password", "Secret123")
        caconfig.set("DEFAULT", "pki_client_database_password", "Secret123")
        caconfig.set("DEFAULT", "pki_backup_keys", "True")
        caconfig.set("DEFAULT", "pki_backup_password", "Secret123")
        caconfig.add_section('Tomcat')
        caconfig.set("Tomcat", "pki_ajp_port", "8009")
        caconfig.set("Tomcat", "pki_tomcat_server", "8005")
        caconfig.add_section("KRA")
        caconfig.set("KRA", "pki_import_admin_cert", "True")
        caconfig.set("KRA", "pki_ds_hostname", "localhost")
        caconfig.set("KRA", "pki_ds_ldap_port", ldap_port)
        caconfig.set("KRA", "pki_ds_password", "Secret123")

        with open(TempFile, "wb") as f:
            caconfig.write(f)

        cmd = "pkispawn -s KRA -f %s -vv" % (TempFile)
        args = shlex.split(cmd)
        stdout, stderr, return_code = PkiTools.Execute(args)
        assert return_code == 0

    def test_InstallOCSP(self, TempFile):
        """ Install OCSP sharing Tomcat Instance of CA """
        ldap_port = DSInstance('FoobarOCSP')
        caconfig = ConfigParser.RawConfigParser()
        caconfig.optionxform = str
        caconfig.set("DEFAULT", "pki_instance_name", 'Foobar1')
        caconfig.set("DEFAULT", "pki_https_port", 8443)
        caconfig.set("DEFAULT", "pki_http_port", 8080)
        caconfig.set("DEFAULT", "pki_token_password", 'Secret123')
        caconfig.set("DEFAULT", "pki_admin_password", 'Secret123')
        caconfig.set("DEFAULT", "pki_security_domain_hostname", 'pki3.example.org')
        caconfig.set("DEFAULT", "pki_security_domain_https_port", "8443")
        caconfig.set("DEFAULT", "pki_security_domain_user", "caadmin")
        caconfig.set("DEFAULT", "pki_security_domain_password", "Secret123")
        caconfig.set("DEFAULT", "pki_client_dir", "/opt/Foobar1")
        caconfig.set("DEFAULT", "pki_client_pkcs12_password", "Secret123")
        caconfig.set("DEFAULT", "pki_client_database_password", "Secret123")
        caconfig.set("DEFAULT", "pki_backup_keys", "True")
        caconfig.set("DEFAULT", "pki_backup_password", "Secret123")
        caconfig.add_section('Tomcat')
        caconfig.set("Tomcat", "pki_ajp_port", "8009")
        caconfig.set("Tomcat", "pki_tomcat_server", "8005")
        caconfig.add_section("OCSP")
        caconfig.set("OCSP", "pki_import_admin_cert", "True")
        caconfig.set("OCSP", "pki_ds_hostname", "localhost")
        caconfig.set("OCSP", "pki_ds_ldap_port", ldap_port)
        caconfig.set("OCSP", "pki_ds_password", "Secret123")

        with open(TempFile, "wb") as f:
            caconfig.write(f)

        cmd = "pkispawn -s OCSP -f %s -vv" % (TempFile)
        args = shlex.split(cmd)
        stdout, stderr, return_code = PkiTools.Execute(args)
        assert return_code == 0
