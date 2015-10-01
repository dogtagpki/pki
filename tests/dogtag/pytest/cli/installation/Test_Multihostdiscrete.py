from pkilib.common.exceptions import DirSrvException
from subprocess import CalledProcessError
import pytest
import constants
import ConfigParser
import time

class Testclass:
    """ Subsystem installation tests under discrete tomcat instaces """
    def class_setup(self, multihost, DSInstance):
        """
        @Setup:
            1. Setup Directory Server Instances on Master 
            2. Setup Directory Server Instances on Clone
        """
        master_ds = DSInstance[0]
        DSInstanceList = [constants.CA_INSTANCE_NAME, 
                constants.KRA_INSTANCE_NAME, 
                constants.OCSP_INSTANCE_NAME,  
                constants.TKS_INSTANCE_NAME,
                constants.TPS_INSTANCE_NAME]
        for Instance in DSInstanceList:
            try:
                ret = master_ds._CreateInstance(Instance)
            except DirSrvException as e:
                mulitihost.master.log.info('Could not setup DS Instance')
                assert False
            else:
                multihost.master.log.info('Successfully setup %s DS Instance' %(Instance))
        clone_ds = DSInstance[1]
        DSInstanceList = [constants.CLONECA_INSTANCE_NAME, 
                constants.CLONEKRA_INSTANCE_NAME, 
                constants.CLONEOCSP_INSTANCE_NAME,  
                constants.CLONETKS_INSTANCE_NAME,
                constants.CLONETPS_INSTANCE_NAME]
        for Instance in DSInstanceList:
            try:
                ret = clone_ds._CreateInstance(Instance)
            except DirSrvException as e:
                mulitihost.clone.log.info('Could not setup DS Instance')
                assert False
            else:
                multihost.clone.log.info('Successfully setup %s DS Instance' %(Instance))
    
    def testConfigCA(self, multihost, TempFile, DSInstance):
        """@Test: Install CA subsystem 
        @Steps:
        1. Setup Directory Server Instance
        2. Setup CA instance with tomcat instance name 'Foobar1'

        @Assert: Verify pkispawn executed successfuly
        """

        #setup CA instance configuration file
        master_ds = DSInstance[0] 
        ldap_port = master_ds.DSUsedPorts[constants.CA_INSTANCE_NAME][0]
        pkiconfig = ConfigParser.RawConfigParser()
        pkiconfig.optionxform = str
        pkiconfig.set("DEFAULT", "pki_instance_name", constants.CA_INSTANCE_NAME)
        pkiconfig.set("DEFAULT", "pki_https_port", constants.CA_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_http_port", constants.CA_HTTP_PORT)
        pkiconfig.set("DEFAULT", "pki_token_password", constants.CA_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_admin_password", constants.CA_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_hostname", multihost.master.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_name", constants.CA_SECURITY_DOMAIN_NAME)
        pkiconfig.set("DEFAULT", "pki_security_domain_password", constants.SECURITY_DOMAIN_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_dir", constants.CA_CLIENT_DIR)
        pkiconfig.set("DEFAULT", "pki_client_pkcs12_password", constants.CLIENT_PKCS12_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_backup_keys", "True")
        pkiconfig.set("DEFAULT", "pki_backup_password", constants.BACKUP_PASSWORD)
        pkiconfig.add_section('Tomcat')
        pkiconfig.set("Tomcat", "pki_ajp_port", constants.CA_AJP_PORT)
        pkiconfig.set("Tomcat", "pki_tomcat_server_port", constants.CA_TOMCAT_PORT)
        pkiconfig.add_section("CA")
        pkiconfig.set("CA", "pki_import_admin_cert", "False")
        pkiconfig.set("CA", "pki_ds_hostname", master_ds.DSInstHost)
        pkiconfig.set("CA", "pki_ds_ldap_port",  ldap_port)
        pkiconfig.set("CA", "pki_ds_password", master_ds.DSRootDNPwd)
        with open(TempFile, "wb") as f:
            pkiconfig.write(f)

        #copy configuration file to master
        multihost.master.transport.put_file(TempFile, '/tmp/ca_cfg')

        #Run pkispawn 
        output = multihost.master.run_command(['pkispawn', '-s', 'CA', '-f', '/tmp/ca_cfg', '-vv'])
        assert 0 == output.returncode
        output = multihost.master.run_command(['scp', '/var/lib/pki/%s/alias/ca_backup_keys.p12' %(constants.CA_INSTANCE_NAME), '%s:/tmp' % (multihost.clone.hostname)])
        assert 0 == output.returncode
        time.sleep(10)

    def testConfigKRA(self, multihost, TempFile,DSInstance):
        """@Test: Install KRA Subsystem on separate Tomcat Instance

        @steps:
        1. Setup Directory Server Instance to be used by KRA subsystems
        2. Create configurtion file specifying details of KRA, DS instance and Ports to be used
        3. Run pkispawn with `pkispawn -s KRA -f <configuration-file> -vv

        @Assert: Verify pkispawn command ran successfuly
        """

        #setup KRA instance configuration file
        master_ds = DSInstance[0]
        ldap_port = master_ds.DSUsedPorts[constants.KRA_INSTANCE_NAME][0]
        pkiconfig = ConfigParser.RawConfigParser()
        pkiconfig.optionxform = str
        pkiconfig.set("DEFAULT", "pki_instance_name", constants.KRA_INSTANCE_NAME)
        pkiconfig.set("DEFAULT", "pki_https_port", constants.KRA_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_http_port", constants.KRA_HTTP_PORT)
        pkiconfig.set("DEFAULT", "pki_token_password", constants.KRA_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_admin_password", constants.KRA_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_security_domain_hostname", multihost.master.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_https_port", constants.CA_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_security_domain_user", constants.CA_ADMIN_USERNAME)
        pkiconfig.set("DEFAULT", "pki_security_domain_password", constants.SECURITY_DOMAIN_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_dir", constants.KRA_CLIENT_DIR)
        pkiconfig.set("DEFAULT", "pki_client_pkcs12_password", constants.CLIENT_PKCS12_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_backup_keys", "True")
        pkiconfig.set("DEFAULT", "pki_backup_password", constants.BACKUP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_database_password", constants.BACKUP_PASSWORD)
        pkiconfig.add_section('Tomcat')
        pkiconfig.set("Tomcat", "pki_ajp_port", constants.KRA_AJP_PORT)
        pkiconfig.set("Tomcat", "pki_tomcat_server_port", constants.KRA_TOMCAT_PORT)
        pkiconfig.add_section("KRA")
        pkiconfig.set("KRA", "pki_import_admin_cert", "False")
        pkiconfig.set("KRA", "pki_ds_hostname", master_ds.DSInstHost)
        pkiconfig.set("KRA", "pki_ds_ldap_port", ldap_port)
        pkiconfig.set("KRA", "pki_ds_password", master_ds.DSRootDNPwd)
        with open(TempFile, "wb") as f:
            pkiconfig.write(f)

        #copy configuration file to master
        multihost.master.transport.put_file(TempFile, '/tmp/kra_cfg')

        #Run pkispawn 
        output = multihost.master.run_command(['pkispawn', '-s', 'KRA', '-f', '/tmp/kra_cfg', '-vv'])
        assert 0 == output.returncode
        output = multihost.master.run_command(['scp', '/var/lib/pki/%s/alias/kra_backup_keys.p12' %(constants.KRA_INSTANCE_NAME), '%s:/tmp' % (multihost.clone.hostname)])
        assert 0 == output.returncode

    def testConfigOCSP(self, multihost, TempFile,DSInstance):
        """@Test: Install OCSP Subsystem on separate Tomcat Instance

        @steps:
        1. Setup Directory Server Instance to be used by OCSP subsystems
        2. Create configurtion file specifying details of OCSP, DS instance and Ports to be used
        3. Run pkispawn with `pkispawn -s KRA -f <configuration-file> -vv

        @Assert: Verify pkispawn command ran successfuly
        """
        #setup OCSP instance configuration file
        master_ds = DSInstance[0]
        ldap_port = master_ds.DSUsedPorts[constants.OCSP_INSTANCE_NAME][0]
        pkiconfig = ConfigParser.RawConfigParser()
        pkiconfig.optionxform = str
        pkiconfig.set("DEFAULT", "pki_instance_name", constants.OCSP_INSTANCE_NAME)
        pkiconfig.set("DEFAULT", "pki_https_port", constants.OCSP_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_http_port", constants.OCSP_HTTP_PORT)
        pkiconfig.set("DEFAULT", "pki_token_password", constants.OCSP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_admin_password", constants.OCSP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_security_domain_hostname", multihost.master.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_https_port", constants.CA_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_security_domain_user", constants.CA_ADMIN_USERNAME)
        pkiconfig.set("DEFAULT", "pki_security_domain_password", constants.SECURITY_DOMAIN_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_dir", constants.OCSP_CLIENT_DIR)
        pkiconfig.set("DEFAULT", "pki_client_pkcs12_password", constants.CLIENT_PKCS12_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_backup_keys", "True")
        pkiconfig.set("DEFAULT", "pki_backup_password", constants.BACKUP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_database_password", constants.BACKUP_PASSWORD)
        pkiconfig.add_section('Tomcat')
        pkiconfig.set("Tomcat", "pki_ajp_port", constants.OCSP_AJP_PORT)
        pkiconfig.set("Tomcat", "pki_tomcat_server_port", constants.OCSP_TOMCAT_PORT)
        pkiconfig.add_section("OCSP")
        pkiconfig.set("OCSP", "pki_import_admin_cert", "False")
        pkiconfig.set("OCSP", "pki_ds_hostname", master_ds.DSInstHost)
        pkiconfig.set("OCSP", "pki_ds_ldap_port", ldap_port)
        pkiconfig.set("OCSP", "pki_ds_password", master_ds.DSRootDNPwd)
        with open(TempFile, "wb") as f:
            pkiconfig.write(f)

        #copy configuration file to master
        multihost.master.transport.put_file(TempFile, '/tmp/ocsp_cfg')

        #Run pkispawn 
        output = multihost.master.run_command(['pkispawn', '-s', 'OCSP', '-f', '/tmp/ocsp_cfg', '-vv'])
        assert 0 == output.returncode
        output = multihost.master.run_command(['scp', '/var/lib/pki/%s/alias/ocsp_backup_keys.p12' %(constants.OCSP_INSTANCE_NAME), '%s:/tmp' % (multihost.clone.hostname)])
        assert 0 == output.returncode

    def testConfigTKS(self, multihost, TempFile,DSInstance):
        """@Test: Install TKS Subsystem on separate Tomcat Instance

        @steps:
        1. Setup Directory Server Instance to be used by TKS subsystems
        2. Create configurtion file specifying details of TKS, DS instance and Ports to be used
        3. Run pkispawn with `pkispawn -s TKS -f <configuration-file> -vv

        @Assert: Verify pkispawn command ran successfuly
        """
        #setup TKS instance configuration file
        master_ds = DSInstance[0]
        ldap_port = master_ds.DSUsedPorts[constants.TKS_INSTANCE_NAME][0]
        pkiconfig = ConfigParser.RawConfigParser()
        pkiconfig.optionxform = str
        pkiconfig.set("DEFAULT", "pki_instance_name", constants.TKS_INSTANCE_NAME)
        pkiconfig.set("DEFAULT", "pki_https_port", constants.TKS_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_http_port", constants.TKS_HTTP_PORT)
        pkiconfig.set("DEFAULT", "pki_token_password", constants.TKS_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_admin_password", constants.TKS_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_security_domain_hostname", multihost.master.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_https_port", constants.CA_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_security_domain_user", constants.CA_ADMIN_USERNAME)
        pkiconfig.set("DEFAULT", "pki_security_domain_password", constants.SECURITY_DOMAIN_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_dir", constants.TKS_CLIENT_DIR)
        pkiconfig.set("DEFAULT", "pki_client_pkcs12_password", constants.CLIENT_PKCS12_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_backup_keys", "True")
        pkiconfig.set("DEFAULT", "pki_backup_password", constants.BACKUP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_database_password", constants.BACKUP_PASSWORD)
        pkiconfig.add_section('Tomcat')
        pkiconfig.set("Tomcat", "pki_ajp_port", constants.TKS_AJP_PORT)
        pkiconfig.set("Tomcat", "pki_tomcat_server_port", constants.TKS_TOMCAT_PORT)
        pkiconfig.add_section("TKS")
        pkiconfig.set("TKS", "pki_import_admin_cert", "False")
        pkiconfig.set("TKS", "pki_ds_hostname", master_ds.DSInstHost)
        pkiconfig.set("TKS", "pki_ds_ldap_port", ldap_port)
        pkiconfig.set("TKS", "pki_ds_password", master_ds.DSRootDNPwd)
        with open(TempFile, "wb") as f:
            pkiconfig.write(f)

        #copy configuration file to master
        multihost.master.transport.put_file(TempFile, '/tmp/tks_cfg')

        #Run pkispawn 
        output = multihost.master.run_command(['pkispawn', '-s', 'TKS', '-f', '/tmp/tks_cfg', '-vv'])
        assert 0 == output.returncode
        output = multihost.master.run_command(['scp', '/var/lib/pki/%s/alias/tks_backup_keys.p12' %(constants.TKS_INSTANCE_NAME), '%s:/tmp' % (multihost.clone.hostname)])
        assert 0 == output.returncode

    
    def testConfigTPS(self, multihost, TempFile,DSInstance):
        """@Test: Install TPS Subsystem on separate Tomcat Instance

        @steps:
        1. Setup Directory Server Instance to be used by TPS subsystems
        2. Create configurtion file specifying details of TPS, DS instance and Ports to be used
        3. Run pkispawn with `pkispawn -s TPS -f <configuration-file> -vv

        @Assert: Verify pkispawn command ran successfuly
        """
        #setup TPS instance configuration file
        master_ds = DSInstance[0]
        ldap_port = master_ds.DSUsedPorts[constants.TPS_INSTANCE_NAME][0]
        pkiconfig = ConfigParser.RawConfigParser()
        pkiconfig.optionxform = str
        pkiconfig.set("DEFAULT", "pki_instance_name", constants.TPS_INSTANCE_NAME)
        pkiconfig.set("DEFAULT", "pki_https_port", constants.TPS_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_http_port", constants.TPS_HTTP_PORT)
        pkiconfig.set("DEFAULT", "pki_token_password", constants.TPS_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_admin_password", constants.TPS_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_security_domain_hostname", multihost.master.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_https_port", constants.CA_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_security_domain_user", constants.CA_ADMIN_USERNAME)
        pkiconfig.set("DEFAULT", "pki_security_domain_password", constants.SECURITY_DOMAIN_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_dir", constants.TPS_CLIENT_DIR)
        pkiconfig.set("DEFAULT", "pki_client_pkcs12_password", constants.CLIENT_PKCS12_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_backup_keys", "True")
        pkiconfig.set("DEFAULT", "pki_backup_password", constants.BACKUP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_database_password", constants.BACKUP_PASSWORD)
        pkiconfig.add_section('Tomcat')
        pkiconfig.set("Tomcat", "pki_ajp_port", constants.TPS_AJP_PORT)
        pkiconfig.set("Tomcat", "pki_tomcat_server_port", constants.TPS_TOMCAT_PORT)
        pkiconfig.add_section("TPS")
        pkiconfig.set("TPS", "pki_import_admin_cert", "False")
        pkiconfig.set("TPS", "pki_ca_uri", "https://%s:%s" % (multihost.master.hostname, constants.CA_HTTPS_PORT))
        pkiconfig.set("TPS", "pki_kra_uri", "https://%s:%s"% (multihost.master.hostname, constants.KRA_HTTPS_PORT))
        pkiconfig.set("TPS", "pki_tks_uri", "https://%s:%s" % (multihost.master.hostname, constants.TKS_HTTPS_PORT ))
        pkiconfig.set("TPS", "pki_authdb_hostname", master_ds.DSInstHost) 
        pkiconfig.set("TPS", "pki_authdb_port", ldap_port)
        pkiconfig.set("TPS", "pki_authdb_basedn", "dc=example,dc=org")
        pkiconfig.set("TPS", "pki_authdb_secure_conn", "False")
        pkiconfig.set("TPS", "pki_import_shared_secret", "False")
        pkiconfig.set("TPS", "pki_enable_server_side_keygen", "False")
        pkiconfig.set("TPS", "pki_ds_hostname", master_ds.DSInstHost)
        pkiconfig.set("TPS", "pki_ds_ldap_port", ldap_port)
        pkiconfig.set("TPS", "pki_ds_password", master_ds.DSRootDNPwd)
        with open(TempFile, "wb") as f:
            pkiconfig.write(f)

        #copy configuration file to master
        multihost.master.transport.put_file(TempFile, '/tmp/tps_cfg')

        #Run pkispawn 
        output = multihost.master.run_command(['pkispawn', '-s', 'TPS', '-f', '/tmp/tps_cfg', '-vv'])
        assert 0 == output.returncode
        output = multihost.master.run_command(['scp', '/var/lib/pki/%s/alias/tps_backup_keys.p12' %(constants.TPS_INSTANCE_NAME), '%s:/tmp' % (multihost.clone.hostname)])
        assert 0 == output.returncode 

    def testConfigCloneCA(self, multihost, TempFile, DSInstance):
        """@Test: Configure Clone CA Subsystem on separate Tomcat Instance

        @steps:
        1. Setup Directory Server Instance to be used by Clone CA Subsystem
        2. Create configurtion file /tmp/ca_cfg specifying details of RootCA,Clone CA port and 
            DS instance
        3. Run pkispawn with `pkispawn -s CA -f /tmp/ca_cfg -vv

        @Assert: Verify pkispawn command ran successfuly
        """

        master_ds = DSInstance[0]
        clone_ds = DSInstance[1]
        master_ldap_port = master_ds.DSUsedPorts[constants.CA_INSTANCE_NAME][0]
        clone_ldap_port = clone_ds.DSUsedPorts[constants.CLONECA_INSTANCE_NAME][0]

        pkiconfig = ConfigParser.RawConfigParser()
        pkiconfig.optionxform = str
        pkiconfig.set("DEFAULT", "pki_instance_name", constants.CLONECA_INSTANCE_NAME)
        pkiconfig.set("DEFAULT", "pki_https_port", constants.CLONECA_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_http_port", constants.CLONECA_HTTP_PORT)
        pkiconfig.set("DEFAULT", "pki_token_password", constants.CLONECA_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_admin_password", constants.CLONECA_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_pkcs12_password", constants.BACKUP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_hostname", multihost.clone.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_hostname", multihost.master.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_user", constants.CA_ADMIN_USERNAME)
        pkiconfig.set("DEFAULT", "pki_security_domain_password", constants.SECURITY_DOMAIN_PASSWORD)
        pkiconfig.add_section('Tomcat')
        pkiconfig.set("Tomcat", "pki_ajp_port", constants.CLONECA_AJP_PORT)
        pkiconfig.set("Tomcat", "pki_tomcat_server_port", constants.CLONECA_TOMCAT_PORT)
        pkiconfig.add_section("CA")
        pkiconfig.set("CA", "pki_clone", "True")
        pkiconfig.set("CA", "pki_clone_pkcs12_path", "/tmp/ca_backup_keys.p12")
        pkiconfig.set("CA", "pki_clone_pkcs12_password", constants.CLIENT_PKCS12_PASSWORD)
        pkiconfig.set("CA", "pki_clone_replicate_schema", "True")
        pkiconfig.set("CA", "pki_clone_uri", "https://%s:%s" %(multihost.master.hostname, constants.CA_HTTPS_PORT))
        pkiconfig.set("CA", "pki_clone_replication_master_port", master_ldap_port)
        pkiconfig.set("CA", "pki_clone_replication_clone_port", clone_ldap_port)
        pkiconfig.set("CA", "pki_ds_ldap_port", clone_ldap_port)
        pkiconfig.set("CA", "pki_ds_password", clone_ds.DSRootDNPwd)
        pkiconfig.set("CA", "pki_ds_remove_data", "True")
        pkiconfig.set("CA", "pki_ds_base_dn", "o=%s-CA"%(constants.CA_INSTANCE_NAME))

        with open(TempFile, "wb") as f:
            pkiconfig.write(f)

        multihost.clone.transport.put_file(TempFile, '/tmp/ca_cfg')
        output = multihost.clone.run_command(['pkispawn', '-s', 'CA', '-f', '/tmp/ca_cfg', '-vv']) 
        assert 0 == output.returncode

    def testConfigCloneKRA(self, multihost, TempFile, DSInstance):
        """@Test: Configure Clone KRA Subsystem on separate Tomcat Instance

        @steps:
        1. Setup Directory Server Instance to be used by Clone KRA Subsystem
        2. Create configurtion file /tmp/kra_cfg specifying details of RootKRA,
            Clone KRA port and  DS instance
        3. Run pkispawn with `pkispawn -s KRA -f /tmp/kra_cfg -vv

        @Assert: Verify pkispawn command ran successfuly
        """

        master_ds = DSInstance[0]
        clone_ds = DSInstance[1]
        master_ldap_port = master_ds.DSUsedPorts[constants.KRA_INSTANCE_NAME][0]
        clone_ldap_port = clone_ds.DSUsedPorts[constants.CLONEKRA_INSTANCE_NAME][0]

        pkiconfig = ConfigParser.RawConfigParser()
        pkiconfig.optionxform = str
        pkiconfig.set("DEFAULT", "pki_instance_name", constants.CLONEKRA_INSTANCE_NAME)
        pkiconfig.set("DEFAULT", "pki_https_port", constants.CLONEKRA_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_http_port", constants.CLONEKRA_HTTP_PORT)
        pkiconfig.set("DEFAULT", "pki_token_password", constants.CLONEKRA_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_admin_password", constants.CLONEKRA_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_hostname", multihost.clone.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_hostname", multihost.master.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_user", constants.CA_ADMIN_USERNAME)
        pkiconfig.set("DEFAULT", "pki_security_domain_password", constants.SECURITY_DOMAIN_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_pkcs12_password", constants.BACKUP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_database_password", constants.CLONEKRA_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_dir", constants.CLONEKRA_CLIENT_DIR)

        pkiconfig.add_section('Tomcat')
        pkiconfig.set("Tomcat", "pki_ajp_port", constants.CLONEKRA_AJP_PORT)
        pkiconfig.set("Tomcat", "pki_tomcat_server_port", constants.CLONEKRA_TOMCAT_PORT)
        pkiconfig.add_section("KRA")
        pkiconfig.set("KRA", "pki_clone", "True")
        pkiconfig.set("KRA", "pki_clone_pkcs12_path", "/tmp/kra_backup_keys.p12")
        pkiconfig.set("KRA", "pki_clone_pkcs12_password", constants.CLIENT_PKCS12_PASSWORD)
        pkiconfig.set("KRA", "pki_clone_replicate_schema", "True")
        pkiconfig.set("KRA", "pki_clone_uri", "https://%s:%s" %(multihost.master.hostname, constants.KRA_HTTPS_PORT))
        pkiconfig.set("KRA", "pki_clone_replication_master_port", master_ldap_port)
        pkiconfig.set("KRA", "pki_clone_replication_clone_port", clone_ldap_port)
        pkiconfig.set("KRA", "pki_ds_ldap_port", clone_ldap_port)
        pkiconfig.set("KRA", "pki_ds_password", clone_ds.DSRootDNPwd)
        pkiconfig.set("KRA", "pki_ds_remove_data", "True")
        pkiconfig.set("KRA", "pki_ds_base_dn", "o=%s-KRA"%(constants.KRA_INSTANCE_NAME))

        with open(TempFile, "wb") as f:
            pkiconfig.write(f)

        multihost.clone.transport.put_file(TempFile, '/tmp/kra_cfg')
        output = multihost.clone.run_command(['pkispawn', '-s', 'KRA', '-f', '/tmp/kra_cfg', '-vv']) 

    def testConfigCloneOCSP(self, multihost, TempFile, DSInstance):
        """@Test: Configure Clone OCSP Subsystem on separate Tomcat Instance

        @steps:
        1. Setup Directory Server Instance to be used by Clone OCSP Subsystem
        2. Create configurtion file /tmp/ocsp_cfg specifying details of RootOCSP,
            Clone OCSP port and  DS instance
        3. Run pkispawn with `pkispawn -s OCSP -f /tmp/ocsp_cfg -vv

        @Assert: Verify pkispawn command ran successfuly
        """

        master_ds = DSInstance[0]
        clone_ds = DSInstance[1]
        master_ldap_port = master_ds.DSUsedPorts[constants.OCSP_INSTANCE_NAME][0]
        clone_ldap_port = clone_ds.DSUsedPorts[constants.CLONEOCSP_INSTANCE_NAME][0]

        pkiconfig = ConfigParser.RawConfigParser()
        pkiconfig.optionxform = str
        pkiconfig.set("DEFAULT", "pki_instance_name", constants.CLONEOCSP_INSTANCE_NAME)
        pkiconfig.set("DEFAULT", "pki_https_port", constants.CLONEOCSP_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_http_port", constants.CLONEOCSP_HTTP_PORT)
        pkiconfig.set("DEFAULT", "pki_token_password", constants.CLONEOCSP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_admin_password", constants.CLONEOCSP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_hostname", multihost.clone.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_hostname", multihost.master.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_user", constants.CA_ADMIN_USERNAME)
        pkiconfig.set("DEFAULT", "pki_security_domain_password", constants.SECURITY_DOMAIN_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_pkcs12_password", constants.BACKUP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_database_password", constants.CLONEOCSP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_dir", constants.CLONEOCSP_CLIENT_DIR)

        pkiconfig.add_section('Tomcat')
        pkiconfig.set("Tomcat", "pki_ajp_port", constants.CLONEOCSP_AJP_PORT)
        pkiconfig.set("Tomcat", "pki_tomcat_server_port", constants.CLONEOCSP_TOMCAT_PORT)
        pkiconfig.add_section("OCSP")
        pkiconfig.set("OCSP", "pki_clone", "True")
        pkiconfig.set("OCSP", "pki_clone_pkcs12_path", "/tmp/ocsp_backup_keys.p12")
        pkiconfig.set("OCSP", "pki_clone_pkcs12_password", constants.CLIENT_PKCS12_PASSWORD)
        pkiconfig.set("OCSP", "pki_clone_replicate_schema", "True")
        pkiconfig.set("OCSP", "pki_clone_uri", "https://%s:%s" %(multihost.master.hostname, constants.OCSP_HTTPS_PORT))
        pkiconfig.set("OCSP", "pki_clone_replication_master_port", master_ldap_port)
        pkiconfig.set("OCSP", "pki_clone_replication_clone_port", clone_ldap_port)
        pkiconfig.set("OCSP", "pki_ds_ldap_port", clone_ldap_port)
        pkiconfig.set("OCSP", "pki_ds_password", clone_ds.DSRootDNPwd)
        pkiconfig.set("OCSP", "pki_ds_remove_data", "True")
        pkiconfig.set("OCSP", "pki_ds_base_dn", "o=%s-OCSP"%(constants.OCSP_INSTANCE_NAME))
        
        with open(TempFile, "wb") as f:
            pkiconfig.write(f)

        multihost.clone.transport.put_file(TempFile, '/tmp/ocsp_cfg')
        output = multihost.clone.run_command(['pkispawn', '-s', 'OCSP', '-f', '/tmp/ocsp_cfg', '-vv']) 
        assert 0 == output.returncode

    def testConfigCloneTKS(self, multihost, TempFile, DSInstance):
        """@Test: Configure Clone TKS Subsystem on separate Tomcat Instance

        @steps:
        1. Setup Directory Server Instance to be used by Clone TKS Subsystem
        2. Create configurtion file /tmp/tks_cfg specifying details of RootKRA,
            Clone TKS port and  DS instance
        3. Run pkispawn with `pkispawn -s TKS -f /tmp/tks_cfg -vv

        @Assert: Verify pkispawn command ran successfuly
        """
        
        master_ds = DSInstance[0]
        clone_ds = DSInstance[1]
        master_ldap_port = master_ds.DSUsedPorts[constants.TKS_INSTANCE_NAME][0]
        clone_ldap_port = clone_ds.DSUsedPorts[constants.CLONETKS_INSTANCE_NAME][0]

        pkiconfig = ConfigParser.RawConfigParser()
        pkiconfig.optionxform = str
        pkiconfig.set("DEFAULT", "pki_instance_name", constants.CLONETKS_INSTANCE_NAME)
        pkiconfig.set("DEFAULT", "pki_https_port", constants.CLONETKS_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_http_port", constants.CLONETKS_HTTP_PORT)
        pkiconfig.set("DEFAULT", "pki_token_password", constants.CLONETKS_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_admin_password", constants.CLONETKS_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_hostname", multihost.clone.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_hostname", multihost.master.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_user", constants.CA_ADMIN_USERNAME)
        pkiconfig.set("DEFAULT", "pki_security_domain_password", constants.SECURITY_DOMAIN_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_pkcs12_password", constants.BACKUP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_database_password", constants.CLONETKS_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_dir", constants.CLONETKS_CLIENT_DIR)

        pkiconfig.add_section('Tomcat')
        pkiconfig.set("Tomcat", "pki_ajp_port", constants.CLONETKS_AJP_PORT)
        pkiconfig.set("Tomcat", "pki_tomcat_server_port", constants.CLONETKS_TOMCAT_PORT)
        pkiconfig.add_section("TKS")
        pkiconfig.set("TKS", "pki_clone", "True")
        pkiconfig.set("TKS", "pki_clone_pkcs12_path", "/tmp/tks_backup_keys.p12")
        pkiconfig.set("TKS", "pki_clone_pkcs12_password", constants.CLIENT_PKCS12_PASSWORD)
        pkiconfig.set("TKS", "pki_clone_replicate_schema", "True")
        pkiconfig.set("TKS", "pki_clone_uri", "https://%s:%s" %(multihost.master.hostname, constants.TKS_HTTPS_PORT))
        pkiconfig.set("TKS", "pki_clone_replication_master_port", master_ldap_port)
        pkiconfig.set("TKS", "pki_clone_replication_clone_port", clone_ldap_port)
        pkiconfig.set("TKS", "pki_ds_ldap_port", clone_ldap_port)
        pkiconfig.set("TKS", "pki_ds_password", clone_ds.DSRootDNPwd)
        pkiconfig.set("TKS", "pki_ds_remove_data", "True")
        pkiconfig.set("TKS", "pki_ds_base_dn", "o=%s-TKS"%(constants.TKS_INSTANCE_NAME))
        
        with open(TempFile, "wb") as f:
            pkiconfig.write(f)

        multihost.clone.transport.put_file(TempFile, '/tmp/tks_cfg')
        output = multihost.clone.run_command(['pkispawn', '-s', 'TKS', '-f', '/tmp/tks_cfg', '-vv']) 
        assert 0 == output.returncode

    @pytest.mark.xfail(reason='BZ-1190184',raises=CalledProcessError)
    def testConfigCloneTPS(self, multihost, TempFile, DSInstance):
        """@Test: Configure Clone TPS Subsystem on separate Tomcat Instance

        @steps:
        1. Setup Directory Server Instance to be used by Clone TPS Subsystem
        2. Create configurtion file /tmp/tps_cfg specifying details of RootTPS,
            Clone TPS port and  DS instance
        3. Run pkispawn with `pkispawn -s TPS -f /tmp/tps_cfg -vv

        @Assert: Verify pkispawn command ran successfuly
        """
        
        master_ds = DSInstance[0]
        clone_ds = DSInstance[1]
        master_ldap_port = master_ds.DSUsedPorts[constants.TPS_INSTANCE_NAME][0]
        clone_ldap_port = clone_ds.DSUsedPorts[constants.CLONETPS_INSTANCE_NAME][0]

        pkiconfig = ConfigParser.RawConfigParser()
        pkiconfig.optionxform = str
        pkiconfig.set("DEFAULT", "pki_instance_name", constants.CLONETPS_INSTANCE_NAME)
        pkiconfig.set("DEFAULT", "pki_https_port", constants.CLONETPS_HTTPS_PORT)
        pkiconfig.set("DEFAULT", "pki_http_port", constants.CLONETPS_HTTP_PORT)
        pkiconfig.set("DEFAULT", "pki_token_password", constants.CLONETPS_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_admin_password", constants.CLONETPS_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_hostname", multihost.clone.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_hostname", multihost.master.hostname)
        pkiconfig.set("DEFAULT", "pki_security_domain_user", constants.CA_ADMIN_USERNAME)
        pkiconfig.set("DEFAULT", "pki_security_domain_password", constants.SECURITY_DOMAIN_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_pkcs12_password", constants.BACKUP_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_database_password", constants.CLONETPS_PASSWORD)
        pkiconfig.set("DEFAULT", "pki_client_dir", constants.CLONETPS_CLIENT_DIR)

        pkiconfig.add_section('Tomcat')
        pkiconfig.set("Tomcat", "pki_ajp_port", constants.CLONETPS_AJP_PORT)
        pkiconfig.set("Tomcat", "pki_tomcat_server_port", constants.CLONETPS_TOMCAT_PORT)
        pkiconfig.add_section("TPS")
        pkiconfig.set("TPS", "pki_clone", "True")
        pkiconfig.set("TPS", "pki_clone_pkcs12_path", "/tmp/tps_backup_keys.p12")
        pkiconfig.set("TPS", "pki_clone_pkcs12_password", constants.CLIENT_PKCS12_PASSWORD)
        pkiconfig.set("TPS", "pki_clone_replicate_schema", "True")
        pkiconfig.set("TPS", "pki_clone_uri", "https://%s:%s" %(multihost.master.hostname, constants.TPS_HTTPS_PORT))
        pkiconfig.set("TPS", "pki_clone_replication_master_port", master_ldap_port)
        pkiconfig.set("TPS", "pki_clone_replication_clone_port", clone_ldap_port)
        pkiconfig.set("TPS", "pki_ds_ldap_port", clone_ldap_port)
        pkiconfig.set("TPS", "pki_ds_password", clone_ds.DSRootDNPwd)
        pkiconfig.set("TPS", "pki_ds_remove_data", "True")
        pkiconfig.set("TPS", "pki_ds_base_dn", "o=%s-TPS"%(constants.TPS_INSTANCE_NAME))
        pkiconfig.set("TPS", "pki_authdb_hostname", multihost.clone.hostname)
        pkiconfig.set("TPS", "pki_authdb_port", clone_ldap_port)
        pkiconfig.set("TPS", "pki_authdb_basedn", clone_ds.DSInstSuffix)
        
        with open(TempFile, "wb") as f:
            pkiconfig.write(f)

        multihost.clone.transport.put_file(TempFile, '/tmp/tps_cfg')
        output = multihost.clone.run_command(['pkispawn', '-s', 'TPS', '-f', '/tmp/tps_cfg', '-vv']) 
        assert 0 == output.returncode

    def testRemoveCloneCA(self, multihost):
        """@Test:  Remove Clone CA Subsystem

        @steps:
        1. Setup Clone CA Instance Foobar-CloneCA
        2. Run pkidestroy -s CA -i Foobar-CloneCA

        @Assert: Verify pkidestroy command ran successfuly
        """
        multihost.clone.run_command(['pkidestroy', '-s', 'CA', '-i',  constants.CLONECA_INSTANCE_NAME])

    def testRemoveCloneKRA(self, multihost):
        """@Test:  Remove Clone KRA Subsystem

        @steps:
        1. Setup Clone KRA Instance Foobar-CloneKRA
        2. Run pkidestroy -s KRA -i Foobar-CloneKRA

        @Assert: Verify pkidestroy command ran successfuly
        """
        multihost.clone.run_command(['pkidestroy', '-s', 'KRA', '-i',  constants.CLONEKRA_INSTANCE_NAME])

    def testRemoveCloneOCSP(self, multihost):
        """@Test:  Remove Clone OCSP Subsystem

        @steps:
        1. Setup Clone OCSP Instance Foobar-CloneOCSP
        2. Run pkidestroy -s OCSP -i Foobar-CloneOCSP

        @Assert: Verify pkidestroy command ran successfuly
        """
        multihost.clone.run_command(['pkidestroy', '-s', 'OCSP', '-i',  constants.CLONEOCSP_INSTANCE_NAME])

    def testRemoveCloneTKS(self, multihost):
        """@Test:  Remove Clone TKS Subsystem

        @steps:
        1. Setup Clone TKS Instance Foobar-CloneTKS
        2. Run pkidestroy -s TKS -i Foobar-CloneTKS

        @Assert: Verify pkidestroy command ran successfuly
        """
        multihost.clone.run_command(['pkidestroy', '-s', 'TKS', '-i',  constants.CLONETKS_INSTANCE_NAME])

    def testRemoveCloneTPS(self, multihost):
        """@Test:  Remove Clone TPS Subsystem

        @steps:
        1. Setup Clone TPS Instance Foobar-CloneTPS
        2. Run pkidestroy -s TPS -i Foobar-CloneTPS

        @Assert: Verify pkidestroy command ran successfuly
        """
        multihost.clone.run_command(['pkidestroy', '-s', 'TPS', '-i',  constants.CLONETPS_INSTANCE_NAME])

    def testRemoveTPS(self, multihost):
        """@Test:  Remove TPS Subsystem

        @steps:
        1. Setup CA subsystem
        2. Setup KRA subsystem
        3. Setup TKS subsystem
        4. Setup TPS subsystem
        5. Run pkidestroy -s TPS -i <Instance Name>

        @Assert: Verify pkidestroy command ran successfuly
        """
        multihost.master.run_command(['pkidestroy', '-s', 'TPS', '-i',  constants.TPS_INSTANCE_NAME])

    def testRemoveTKS(self, multihost):
        """@Test:  Remove TKS Subsystem

        @steps:
        1. Setup CA subsystem
        2. Setup KRA subsystem
        3. Setup TKS subsystem
        4. Run pkidestroy -s TKS -i <Instance Name>

        @Assert: Verify pkidestroy command ran successfuly
        """
        multihost.master.run_command(['pkidestroy', '-s', 'TKS', '-i',  constants.TKS_INSTANCE_NAME])

    def testRemoveOCSP(self, multihost):
        """@Test:  Remove OCSP Subsystem

        @steps:
        1. Setup CA subsystem
        2. Setup OCSP subsystem
        3. Run pkidestroy -s OCSP -i <Instance Name>

        @Assert: Verify pkidestroy command ran successfuly
        """
        multihost.master.run_command(['pkidestroy', '-s', 'OCSP', '-i',  constants.OCSP_INSTANCE_NAME])

    def testRemoveKRA(self, multihost):
        """@Test:  Remove KRA Subsystem

        @steps:
        1. Setup CA subsystem
        2. Setup KRA subsystem
        3. Run pkidestroy -s KRA -i <Instance Name>

        @Assert: Verify pkidestroy command ran successfuly
        """
        multihost.master.run_command(['pkidestroy', '-s', 'KRA', '-i',  constants.KRA_INSTANCE_NAME])

    def testRemoveCA(self, multihost):
        """@Test:  Remove CA Subsystem

        @steps:
        1. Setup CA subsystem
        2. Run pkidestroy -s CA -i <Instance Name>

        @Assert: Verify pkidestroy command ran successfuly
        """
        multihost.master.run_command(['pkidestroy', '-s', 'CA', '-i',  constants.CA_INSTANCE_NAME])

    def class_teardown(self, multihost, DSInstance):
        """
        @Teardown:
        1. Remove Directory Server instances from Master
        2. Remove Directory Server instances from clone
        """
        multihost.master.log.info('Remove Directory Server instances from Master')
        print(".... teardown .... ")
        master_ds = DSInstance[0]
        DSInstanceList = [constants.CA_INSTANCE_NAME, 
                constants.KRA_INSTANCE_NAME, 
                constants.OCSP_INSTANCE_NAME,  
                constants.TKS_INSTANCE_NAME,
                constants.TPS_INSTANCE_NAME]
        for Instance in DSInstanceList:
            ret = master_ds._RemoveInstance(Instance)
            assert ret == True
        multihost.master.log.info('Remove Directory Server instances from Clone')
        clone_ds = DSInstance[1]
        DSInstanceList = [constants.CLONECA_INSTANCE_NAME, 
                constants.CLONEKRA_INSTANCE_NAME, 
                constants.CLONEOCSP_INSTANCE_NAME,  
                constants.CLONETKS_INSTANCE_NAME,
                constants.CLONETPS_INSTANCE_NAME]
        for Instance in DSInstanceList:
            ret = clone_ds._RemoveInstance(Instance)
            assert ret == True
