#!/usr/bin/jython

# System Java Imports
from java.io import BufferedReader
from java.io import ByteArrayInputStream
from java.io import FileReader
from java.io import IOException
from java.lang import Integer
from java.lang import String as javastring
from java.lang import System as javasystem
from java.net import URISyntaxException
from java.security import KeyPair
from java.security import NoSuchAlgorithmException
from java.util import ArrayList
from java.util import Collection
from java.util import Iterator
from org.python.core import PyDictionary
import jarray


# System Python Imports
import ConfigParser
import os
import re
import sys
pki_python_module_path = os.path.join(sys.prefix,
                                      "lib",
                                      "python" + str(sys.version_info[0]) +
                                      "." + str(sys.version_info[1]),
                                      "site-packages",
                                      "pki",
                                      "deployment",
                                      "configuration.jy")
sys.path.append(pki_python_module_path)


# http://www.jython.org/jythonbook/en/1.0/appendixB.html#working-with-classpath
###############################################################################
# from http://forum.java.sun.com/thread.jspa?threadID=300557
#
# Author:   SG Langer Jan 2007 translated the above Java to this Jython class
# Purpose:  Allow runtime additions of new Class/jars either from local files
#           or URL
###############################################################################
class classPathHacker:
    import java.lang.reflect.Method
    import java.io.File
    import java.net.URL
    import java.net.URLClassLoader
    import jarray

    def addFile(self, s):
        ##################################################
        # Purpose:  If adding a file/jar call this first
        #           with s = path_to_jar
        ##################################################

        # make a URL out of 's'
        f = self.java.io.File (s)
        u = f.toURL ()
        a = self.addURL (u)
        return a

    def addURL(self, u):
        ###########################################
        # Purpose:  Call this with u= URL for the
        #           new Class/jar to be loaded
        ###########################################

        parameters = self.jarray.array([self.java.net.URL],
                                       self.java.lang.Class)
        sysloader =  self.java.lang.ClassLoader.getSystemClassLoader()
        sysclass = self.java.net.URLClassLoader
        method = sysclass.getDeclaredMethod("addURL", parameters)
        a = method.setAccessible(1)
        jar_a = self.jarray.array([u], self.java.lang.Object)
        b = method.invoke(sysloader, jar_a)
        return u

# PKI Python Imports
import pkiconfig as config
import pkimessages as log

# Dynamically Load Additional Java Jars ('append' to existing classpath)
jarLoad = classPathHacker()
#     Webserver Jars
jarLoad.addFile("/usr/share/java/httpcomponents/httpclient.jar")
jarLoad.addFile("/usr/share/java/httpcomponents/httpcore.jar")
jarLoad.addFile("/usr/share/java/apache-commons-cli.jar")
jarLoad.addFile("/usr/share/java/apache-commons-codec.jar")
jarLoad.addFile("/usr/share/java/apache-commons-logging.jar")
jarLoad.addFile("/usr/share/java/istack-commons-runtime.jar")

#     Resteasy Jars
RESTEASY_ROOT = "resteasy"
if config.is_rhel():
    RESTEASY_ROOT = "resteasy-base"

jarLoad.addFile("/usr/share/java/glassfish-jaxb/jaxb-impl.jar")
jarLoad.addFile("/usr/share/java/" + RESTEASY_ROOT + "/jaxrs-api.jar")
jarLoad.addFile("/usr/share/java/" + RESTEASY_ROOT + "/resteasy-atom-provider.jar")
jarLoad.addFile("/usr/share/java/" + RESTEASY_ROOT + "/resteasy-jaxb-provider.jar")
jarLoad.addFile("/usr/share/java/" + RESTEASY_ROOT + "/resteasy-jaxrs.jar")
jarLoad.addFile("/usr/share/java/" + RESTEASY_ROOT + "/resteasy-jettison-provider.jar")
jarLoad.addFile("/usr/share/java/scannotation.jar")
#     PKI Jars
jarLoad.addFile("/usr/share/java/pki/pki-certsrv.jar")
jarLoad.addFile("/usr/share/java/pki/pki-client.jar")
jarLoad.addFile("/usr/share/java/pki/pki-cmsutil.jar")
jarLoad.addFile("/usr/share/java/pki/pki-nsutil.jar")
#     JSS JNI Jars
#
#         NOTE:  Always load 64-bit JNI 'jss4.jar'
#                PRIOR to 32-bit JNI 'jss4.jar'
#
jarLoad.addFile("/usr/lib64/java/jss4.jar")
jarLoad.addFile("/usr/lib/java/jss4.jar")


# Apache Commons Java Imports
from org.apache.commons.cli import CommandLine
from org.apache.commons.cli import CommandLineParser
from org.apache.commons.cli import HelpFormatter
from org.apache.commons.cli import Options
from org.apache.commons.cli import ParseException
from org.apache.commons.cli import PosixParser


# JSS Java Imports
from org.mozilla.jss import CryptoManager
from org.mozilla.jss.asn1 import ASN1Util
from org.mozilla.jss.asn1 import BIT_STRING
from org.mozilla.jss.asn1 import INTEGER
from org.mozilla.jss.asn1 import InvalidBERException
from org.mozilla.jss.asn1 import SEQUENCE
from org.mozilla.jss.crypto import AlreadyInitializedException
from org.mozilla.jss.crypto import CryptoToken
from org.mozilla.jss.crypto import KeyPairAlgorithm
from org.mozilla.jss.crypto import KeyPairGenerator
from org.mozilla.jss.crypto import TokenException
from org.mozilla.jss.pkix.crmf import CertReqMsg
from org.mozilla.jss.pkix.crmf import CertRequest
from org.mozilla.jss.pkix.crmf import CertTemplate
from org.mozilla.jss.pkix.crmf import POPOPrivKey
from org.mozilla.jss.pkix.crmf import ProofOfPossession
from org.mozilla.jss.pkix.primitive import Name
from org.mozilla.jss.pkix.primitive import SubjectPublicKeyInfo
from org.mozilla.jss.util import Password


# PKI Java Imports
from com.netscape.certsrv.system import SystemConfigClient
from com.netscape.certsrv.system import SystemCertData
from com.netscape.certsrv.system import ConfigurationRequest
from com.netscape.certsrv.system import ConfigurationResponse
from com.netscape.cmsutil.util import Utils
from netscape.security.x509 import X500Name

# PKI Deployment Jython Helper Functions
def generateCRMFRequest(token, keysize, subjectdn, dualkey):
        kg = token.getKeyPairGenerator(KeyPairAlgorithm.RSA)
        x = Integer(keysize)
        key_len = x.intValue()
        kg.initialize(key_len)
        # 1st key pair
        pair = kg.genKeyPair()
        # create CRMF
        certTemplate = CertTemplate()
        certTemplate.setVersion(INTEGER(2))
        if not subjectdn is None:
            name = X500Name(subjectdn)
            cs = ByteArrayInputStream(name.getEncoded())
            n = Name.getTemplate().decode(cs)
            certTemplate.setSubject(n)
        certTemplate.setPublicKey(SubjectPublicKeyInfo(pair.getPublic()))
        seq = SEQUENCE()
        certReq = CertRequest(INTEGER(1), certTemplate, seq)
        popdata = jarray.array([0x0,0x3,0x0], 'b')
        pop = ProofOfPossession.createKeyEncipherment(
                  POPOPrivKey.createThisMessage(BIT_STRING(popdata, 3)))
        crmfMsg = CertReqMsg(certReq, pop, None)
        s1 = SEQUENCE()
        # 1st : Encryption key
        s1.addElement(crmfMsg)
        # 2nd : Signing Key
        if config.str2bool(dualkey):
            javasystem.out.println(log.PKI_JYTHON_IS_DUALKEY)
            seq1 = SEQUENCE()
            certReqSigning = CertRequest(INTEGER(1), certTemplate, seq1)
            signingMsg = CertReqMsg(certReqSigning, pop, None)
            s1.addElement(signingMsg)
        encoded = jarray.array(ASN1Util.encode(s1), 'b')
        # encoder = BASE64Encoder()
        # Req1 = encoder.encodeBuffer(encoded)
        Req1 = Utils.base64encode(encoded)
        return Req1

COMMENT_CHAR = '#'
OPTION_CHAR =  '='
def read_simple_configuration_file(filename):
    values = {}
    f = open(filename)
    for line in f:
        # First, remove comments:
        if COMMENT_CHAR in line:
            # split on comment char, keep only the part before
            line, comment = line.split(COMMENT_CHAR, 1)
        # Second, find lines with an name=value:
        if OPTION_CHAR in line:
            # split on name char:
            name, value = line.split(OPTION_CHAR, 1)
            # strip spaces:
            name = name.strip()
            value = value.strip()
            # store in dictionary:
            values[name] = value
    f.close()
    return values


# PKI Deployment 'security databases' Class
class security_databases:
    def initialize_token(self, pki_database_path, log_level):
        try:
            if log_level >= config.PKI_JYTHON_INFO_LOG_LEVEL:
                print "%s %s '%s'" %\
                      (log.PKI_JYTHON_INDENTATION_2,
                       log.PKI_JYTHON_INITIALIZING_TOKEN,
                       pki_database_path)
            CryptoManager.initialize(pki_database_path)
        except AlreadyInitializedException, e:
            # it is ok if it is already initialized
            pass
        except Exception, e:
            javasystem.out.println(log.PKI_JYTHON_INITIALIZATION_ERROR +\
                                   " " + str(e))
            javasystem.exit(1)

    def log_into_token(self, pki_database_path, password_conf, log_level):
        token = None
        try:
            if log_level >= config.PKI_JYTHON_INFO_LOG_LEVEL:
                print "%s %s '%s'" %\
                      (log.PKI_JYTHON_INDENTATION_2,
                       log.PKI_JYTHON_LOG_INTO_TOKEN,
                       pki_database_path)
            manager = CryptoManager.getInstance()
            token = manager.getInternalKeyStorageToken()
            # Retrieve 'password' from client-side 'password_conf'
            #
            #     NOTE:  For now, ONLY read the first line
            #            (which contains "password")
            #
            fd = open(password_conf, "r")
            token_pwd = fd.readline()
            fd.close
            # Convert 'token_pwd' into a 'java char[]'
            jtoken_pwd = jarray.array(token_pwd, 'c')
            password = Password(jtoken_pwd)
            try:
                token.login(password)
            except Exception, e:
                javasystem.out.println(log.PKI_JYTHON_LOGIN_EXCEPTION +\
                                       " " + str(e))
                if not token.isLoggedIn():
                    token.initPassword(password, password)
                javasystem.exit(1)
        except Exception, e:
            javasystem.out.println(log.PKI_JYTHON_TOKEN_LOGIN_EXCEPTION +\
                                   " " + str(e))
            javasystem.exit(1)
        return token


# PKI Deployment 'REST Client' Class
class rest_client:
    client = None
    master = None
    sensitive = None

    def initialize(self, client_config, master, sensitive):
        try:
            self.master = master
            self.sensitive = sensitive
            log_level = master['pki_jython_log_level']
            if log_level >= config.PKI_JYTHON_INFO_LOG_LEVEL:
                print "%s %s '%s'" %\
                      (log.PKI_JYTHON_INDENTATION_2,
                       log.PKI_JYTHON_INITIALIZING_REST_CLIENT,
                       client_config.serverURI)
            self.client = SystemConfigClient(client_config)
            return self.client
        except URISyntaxException, e:
            e.printStackTrace()
            javasystem.exit(1)

    def set_existing_security_domain(self, data):
        data.setSecurityDomainType(ConfigurationRequest.EXISTING_DOMAIN)
        data.setSecurityDomainUri(self.master['pki_security_domain_uri'])
        data.setSecurityDomainUser(self.master['pki_security_domain_user'])
        data.setSecurityDomainPassword(
            self.sensitive['pki_security_domain_password'])

    def set_new_security_domain(self, data):
        data.setSecurityDomainType(ConfigurationRequest.NEW_DOMAIN)
        data.setSecurityDomainName(self.master['pki_security_domain_name'])

    def set_cloning_parameters(self, data):
        data.setIsClone("true")
        data.setCloneUri(self.master['pki_clone_uri'])
        data.setP12File(self.master['pki_clone_pkcs12_path'])
        data.setP12Password(self.sensitive['pki_clone_pkcs12_password'])
        data.setReplicateSchema(self.master['pki_clone_replicate_schema'])
        data.setReplicationSecurity(
            self.master['pki_clone_replication_security'])
        if self.master['pki_clone_replication_master_port']:
            data.setMasterReplicationPort(
                self.master['pki_clone_replication_master_port'])
        if self.master['pki_clone_replication_clone_port']:
            data.setCloneReplicationPort(
                self.master['pki_clone_replication_clone_port'])

    def set_database_parameters(self, data):
        data.setDsHost(self.master['pki_ds_hostname'])
        data.setDsPort(self.master['pki_ds_ldap_port'])
        data.setBaseDN(self.master['pki_ds_base_dn'])
        data.setBindDN(self.master['pki_ds_bind_dn'])
        data.setDatabase(self.master['pki_ds_database'])
        data.setBindpwd(self.sensitive['pki_ds_password'])
        if config.str2bool(self.master['pki_ds_remove_data']):
            data.setRemoveData("true")
        else:
            data.setRemoveData("false")
        if config.str2bool(self.master['pki_ds_secure_connection']):
            data.setSecureConn("true")
        else:
            data.setSecureConn("false")

    def set_backup_parameters(self, data):
        if config.str2bool(self.master['pki_backup_keys']):
            data.setBackupKeys("true")
            data.setBackupFile(self.master['pki_backup_keys_p12'])
            data.setBackupPassword(self.sensitive['pki_backup_password'])
        else:
            data.setBackupKeys("false")

    def set_admin_parameters(self, token, data):
        data.setAdminEmail(self.master['pki_admin_email'])
        data.setAdminName(self.master['pki_admin_name'])
        data.setAdminPassword(self.sensitive['pki_admin_password'])
        data.setAdminProfileID(self.master['pki_admin_profile_id'])
        data.setAdminUID(self.master['pki_admin_uid'])
        data.setAdminSubjectDN(self.master['pki_admin_subject_dn'])
        if self.master['pki_admin_cert_request_type'] == "crmf":
            data.setAdminCertRequestType("crmf")
            if config.str2bool(self.master['pki_admin_dualkey']):
                crmf_request = generateCRMFRequest(
                                   token,
                                   self.master['pki_admin_keysize'],
                                   self.master['pki_admin_subject_dn'],
                                   "true")
            else:
                crmf_request = generateCRMFRequest(
                                   token,
                                   self.master['pki_admin_keysize'],
                                   self.master['pki_admin_subject_dn'],
                                   "false")
            data.setAdminCertRequest(crmf_request)
        else:
            javasystem.out.println(log.PKI_JYTHON_CRMF_SUPPORT_ONLY)
            javasystem.exit(1)

    def create_system_cert(self, tag):
        cert = SystemCertData()
        cert.setTag(self.master["pki_%s_tag" % tag])
        cert.setKeyAlgorithm(self.master["pki_%s_key_algorithm" % tag])
        cert.setKeySize(self.master["pki_%s_key_size" % tag])
        cert.setKeyType(self.master["pki_%s_key_type" % tag])
        cert.setNickname(self.master["pki_%s_nickname" % tag])
        cert.setSubjectDN(self.master["pki_%s_subject_dn" % tag])
        cert.setToken(self.master["pki_%s_token" % tag])
        return cert

    def retrieve_existing_server_cert(self, cfg_file):
        cs_cfg = read_simple_configuration_file(cfg_file)
        cstype = cs_cfg.get('cs.type').lower()
        cert = SystemCertData()
        cert.setTag(self.master["pki_ssl_server_tag"])
        cert.setKeyAlgorithm(self.master["pki_ssl_server_key_algorithm"])
        cert.setKeySize(self.master["pki_ssl_server_key_size"])
        cert.setKeyType(self.master["pki_ssl_server_key_type"])
        cert.setNickname(cs_cfg.get(cstype + ".sslserver.nickname"))
        cert.setCert(cs_cfg.get(cstype + ".sslserver.cert"))
        cert.setRequest(cs_cfg.get(cstype + ".sslserver.certreq"))
        cert.setSubjectDN(self.master["pki_ssl_server_subject_dn"])
        cert.setToken(cs_cfg.get(cstype + ".sslserver.tokenname"))
        return cert

    def tomcat_instance_subsystems(self):
        # Return list of PKI subsystems in the specified tomcat instance
        rv = []
        try:
            for subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
                path = self.master['pki_instance_path'] + "/" + subsystem.lower()
                if os.path.exists(path) and os.path.isdir(path):
                    rv.append(subsystem)
        except Exception, e:
            javasystem.out.println(
                log.PKI_JYTHON_JAVA_CONFIGURATION_EXCEPTION + " " + str(e))
            javasystem.exit(1)
        return rv


    def construct_pki_configuration_data(self, token):
        data = None
        master = self.master
        if master['pki_jython_log_level'] >= config.PKI_JYTHON_INFO_LOG_LEVEL:
            print "%s %s '%s'" %\
                  (log.PKI_JYTHON_INDENTATION_2,
                   log.PKI_JYTHON_CONSTRUCTING_PKI_DATA,
                   master['pki_subsystem'])
        data = ConfigurationRequest()

        # Miscellaneous Configuration Information
        data.setPin(self.sensitive['pki_one_time_pin'])
        data.setToken(ConfigurationRequest.TOKEN_DEFAULT)
        data.setSubsystemName(master['pki_subsystem_name'])

        # Hierarchy
        if master['pki_instance_type'] == "Tomcat":
            if master['pki_subsystem'] == "CA":
                if config.str2bool(master['pki_clone']):
                    # Cloned CA
                    # alee - is this correct?
                    data.setHierarchy("root")
                elif config.str2bool(master['pki_external']):
                    # External CA
                    data.setHierarchy("join")
                elif config.str2bool(master['pki_subordinate']):
                    # Subordinate CA
                    data.setHierarchy("join")
                else:
                    # PKI CA
                    data.setHierarchy("root")

        # Cloning parameters
        if master['pki_instance_type'] == "Tomcat":
            if config.str2bool(master['pki_clone']):
                self.set_cloning_parameters(data)
            else:
                data.setIsClone("false")

        # Security Domain
        if master['pki_subsystem'] != "CA" or\
           config.str2bool(master['pki_clone']) or\
           config.str2bool(master['pki_subordinate']):
            # PKI KRA, PKI OCSP, PKI RA, PKI TKS, PKI TPS,
            # CA Clone, KRA Clone, OCSP Clone, TKS Clone, or
            # Subordinate CA
            self.set_existing_security_domain(data)
        elif not config.str2bool(master['pki_external']):
            # PKI CA
            self.set_new_security_domain(data)

        if master['pki_subsystem'] != "RA":
            self.set_database_parameters(data)

        if master['pki_instance_type'] == "Tomcat":
            self.set_backup_parameters(data)

        if not config.str2bool(master['pki_clone']):
            self.set_admin_parameters(token, data)

        # Issuing CA Information
        if master['pki_subsystem'] != "CA" or\
           config.str2bool(master['pki_clone']) or\
           config.str2bool(master['pki_subordinate']) or\
           config.str2bool(master['pki_external']):
            # PKI KRA, PKI OCSP, PKI RA, PKI TKS, PKI TPS,
            # CA Clone, KRA Clone, OCSP Clone, TKS Clone,
            # Subordinate CA, or External CA
            data.setIssuingCA(master['pki_issuing_ca'])

        # Create system certs
        systemCerts = ArrayList()

        # Create 'CA Signing Certificate'
        if master['pki_subsystem'] == "CA":
            if not config.str2bool(master['pki_clone']):
                cert = self.create_system_cert("ca_signing")
                cert.setSigningAlgorithm(
                    master['pki_ca_signing_signing_algorithm'])
                systemCerts.add(cert)

        # Create 'OCSP Signing Certificate'
        if not config.str2bool(master['pki_clone']):
            if master['pki_subsystem'] == "CA" or\
               master['pki_subsystem'] == "OCSP":
                # External CA, Subordinate CA, PKI CA, or PKI OCSP
                cert2 = self.create_system_cert("ocsp_signing")
                cert2.setSigningAlgorithm(
                    master['pki_ocsp_signing_signing_algorithm'])
                systemCerts.add(cert2)

        # Create 'SSL Server Certificate'
        # all subsystems

        # create new sslserver cert only if this is a new instance
        cert3 = None
        system_list = self.tomcat_instance_subsystems()
        if len(system_list) >= 2:
            data.setGenerateServerCert("false")
            for subsystem in system_list:
                dst = master['pki_instance_path'] + '/conf/' +\
                    subsystem.lower() + '/CS.cfg' 
                if subsystem != master['pki_subsystem'] and \
                   os.path.exists(dst):
                    cert3 = self.retrieve_existing_server_cert(dst)
                    break
        else:
            cert3 = self.create_system_cert("ssl_server")
        systemCerts.add(cert3)

        # Create 'Subsystem Certificate'
        if not config.str2bool(master['pki_clone']):
            cert4 = self.create_system_cert("subsystem")
            systemCerts.add(cert4)

        # Create 'Audit Signing Certificate'
        if not config.str2bool(master['pki_clone']):
            if master['pki_subsystem'] != "RA":
                cert5 = self.create_system_cert("audit_signing")
                cert5.setSigningAlgorithm(
                    master['pki_audit_signing_signing_algorithm'])
                systemCerts.add(cert5)

        # Create DRM Transport and storage Certificates
        if not config.str2bool(master['pki_clone']):
            if master['pki_subsystem'] == "KRA":
                cert6 = self.create_system_cert("transport")
                systemCerts.add(cert6)

                cert7 = self.create_system_cert("storage")
                systemCerts.add(cert7)

        data.setSystemCerts(systemCerts)

        return data

    def configure_pki_data(self, data):
        master = self.master
        if master['pki_jython_log_level'] >= config.PKI_JYTHON_INFO_LOG_LEVEL:
            print "%s %s '%s'" %\
                  (log.PKI_JYTHON_INDENTATION_2,
                   log.PKI_JYTHON_CONFIGURING_PKI_DATA,
                   master['pki_subsystem'])
        try:
            response = self.client.configure(data)
            javasystem.out.println(log.PKI_JYTHON_RESPONSE_STATUS +\
                                   " " + response.getStatus())
            certs = response.getSystemCerts()
            iterator = certs.iterator()
            while iterator.hasNext():
                cdata = iterator.next()
                javasystem.out.println(log.PKI_JYTHON_CDATA_TAG + " " +\
                                       cdata.getTag())
                javasystem.out.println(log.PKI_JYTHON_CDATA_CERT + " " +\
                                       cdata.getCert())
                javasystem.out.println(log.PKI_JYTHON_CDATA_REQUEST + " " +\
                                       cdata.getRequest())
            # Cloned PKI subsystems do not return an Admin Certificate
            if not config.str2bool(master['pki_clone']):
                admin_cert = response.getAdminCert().getCert()
                javasystem.out.println(log.PKI_JYTHON_RESPONSE_ADMIN_CERT +\
                                       " " + admin_cert)
                # Store the Administration Certificate in a file
                admin_cert_file = os.path.join(
                    master['pki_client_dir'],
                    master['pki_client_admin_cert'])
                admin_cert_bin_file = admin_cert_file + ".der"
                javasystem.out.println(log.PKI_JYTHON_ADMIN_CERT_SAVE +\
                                       " " + "'" + admin_cert_file + "'")
                FILE = open(admin_cert_file, "w")
                FILE.write(admin_cert)
                FILE.close()
                # convert the cert file to binary
                command = "AtoB "+ admin_cert_file + " " + admin_cert_bin_file
                javasystem.out.println(log.PKI_JYTHON_ADMIN_CERT_ATOB +\
                    " " + "'" + command + "'")
                os.system(command)

                # Since Jython runs under Java, it does NOT support the
                # following operating system specific command:
                #
                #     os.chmod(
                #         admin_cert_file,
                #         config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS)
                #
                # Emulate it with a system call.
                command = "chmod" + " 660 " + admin_cert_file
                javasystem.out.println(
                    log.PKI_JYTHON_CHMOD +\
                    " " + "'" + command + "'")
                os.system(command)

                command = "chmod" + " 660 " + admin_cert_bin_file
                javasystem.out.println(
                    log.PKI_JYTHON_CHMOD +\
                    " " + "'" + command + "'")
                os.system(command)

                # Import the Administration Certificate
                # into the client NSS security database
                command = "certutil" + " " +\
                          "-A" + " " +\
                          "-n" + " " + "\"" +\
                          re.sub("&#39;",
                                 "'", master['pki_admin_nickname']) +\
                          "\"" + " " +\
                          "-t" + " " +\
                          "\"" + "u,u,u" + "\"" + " " +\
                          "-f" + " " +\
                          master['pki_client_password_conf'] + " " +\
                          "-d" + " " +\
                          master['pki_client_database_dir'] + " " +\
                          "-i" + " " +\
                          admin_cert_bin_file
                javasystem.out.println(
                    log.PKI_JYTHON_ADMIN_CERT_IMPORT +\
                    " " + "'" + command + "'")
                os.system(command)
                # Export the Administration Certificate from the
                # client NSS security database into a PKCS #12 file
                command = "pk12util" + " " +\
                          "-o" + " " +\
                          master['pki_client_admin_cert_p12'] + " " +\
                          "-n" + " " + "\"" +\
                          re.sub("&#39;",
                                 "'", master['pki_admin_nickname']) +\
                          "\"" + " " +\
                          "-d" + " " +\
                          master['pki_client_database_dir'] + " " +\
                          "-k" + " " +\
                          master['pki_client_password_conf'] + " " +\
                          "-w" + " " +\
                          master['pki_client_pkcs12_password_conf']
                javasystem.out.println(
                    log.PKI_JYTHON_ADMIN_CERT_EXPORT +\
                    " " + "'" + command + "'")
                os.system(command)
                # Since Jython runs under Java, it does NOT support the
                # following operating system specific command:
                #
                # os.chmod(master['pki_client_admin_cert_p12'],
                #     config.\
                #     PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)
                #
                # Emulate it with a system call.
                command = "chmod" + " " + "664" + " " +\
                          master['pki_client_admin_cert_p12']
                javasystem.out.println(
                    log.PKI_JYTHON_CHMOD +\
                    " " + "'" + command + "'")
                os.system(command)
        except Exception, e:
            javasystem.out.println(
                log.PKI_JYTHON_JAVA_CONFIGURATION_EXCEPTION + " " + str(e))
            javasystem.exit(1)
        return


# PKI Deployment Jython Class Instances
security_databases = security_databases()
rest_client = rest_client()
