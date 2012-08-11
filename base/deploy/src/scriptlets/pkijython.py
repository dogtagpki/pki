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
jarLoad.addFile("/usr/share/java/glassfish-jaxb/jaxb-impl.jar")
jarLoad.addFile("/usr/share/java/resteasy/jaxrs-api.jar")
jarLoad.addFile("/usr/share/java/resteasy/resteasy-atom-provider.jar")
jarLoad.addFile("/usr/share/java/resteasy/resteasy-jaxb-provider.jar")
jarLoad.addFile("/usr/share/java/resteasy/resteasy-jaxrs.jar")
jarLoad.addFile("/usr/share/java/resteasy/resteasy-jettison-provider.jar")
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
from com.netscape.cms.client.system import SystemConfigClient
from com.netscape.certsrv.system import SystemCertData
from com.netscape.certsrv.system import ConfigurationRequest
from com.netscape.certsrv.system import ConfigurationResponse
from com.netscape.cmsutil.util import Utils
from netscape.security.x509 import X500Name


# PKI Python Imports
import pkiconfig as config
import pkimessages as log


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


# PKI Deployment 'security databases' Class
class security_databases:
    def initialize_token(self, pki_database_path, pki_dry_run_flag, log_level):
        try:
            if log_level >= config.PKI_JYTHON_INFO_LOG_LEVEL:
                print "%s %s '%s'" %\
                      (log.PKI_JYTHON_INDENTATION_2,
                       log.PKI_JYTHON_INITIALIZING_TOKEN,
                       pki_database_path)
            if not pki_dry_run_flag:
                CryptoManager.initialize(pki_database_path)
        except AlreadyInitializedException, e:
            # it is ok if it is already initialized
            pass
        except Exception, e:
            javasystem.out.println(log.PKI_JYTHON_INITIALIZATION_ERROR +\
                                   " " + str(e))
            javasystem.exit(1)

    def log_into_token(self, pki_database_path, password_conf,
                       pki_dry_run_flag, log_level):
        token = None
        try:
            if log_level >= config.PKI_JYTHON_INFO_LOG_LEVEL:
                print "%s %s '%s'" %\
                      (log.PKI_JYTHON_INDENTATION_2,
                       log.PKI_JYTHON_LOG_INTO_TOKEN,
                       pki_database_path)
            if not pki_dry_run_flag:
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

    def initialize(self, client_config, pki_dry_run_flag, log_level):
        try:
            if log_level >= config.PKI_JYTHON_INFO_LOG_LEVEL:
                print "%s %s '%s'" %\
                      (log.PKI_JYTHON_INDENTATION_2,
                       log.PKI_JYTHON_INITIALIZING_REST_CLIENT,
                       client_config.serverURI)
            if not pki_dry_run_flag:
                self.client = SystemConfigClient(client_config)
            return self.client
        except URISyntaxException, e:
            e.printStackTrace()
            javasystem.exit(1)

    def construct_pki_configuration_data(self, master, sensitive, token):
        data = None
        if master['pki_jython_log_level'] >= config.PKI_JYTHON_INFO_LOG_LEVEL:
            print "%s %s '%s'" %\
                  (log.PKI_JYTHON_INDENTATION_2,
                   log.PKI_JYTHON_CONSTRUCTING_PKI_DATA,
                   master['pki_subsystem'])
        if not master['pki_dry_run_flag']:
            data = ConfigurationRequest()
            # Miscellaneous Configuration Information
            data.setPin(sensitive['pki_one_time_pin'])
            data.setToken(ConfigurationRequest.TOKEN_DEFAULT)
            if master['pki_instance_type'] == "Tomcat":
                data.setSubsystemName(master['pki_subsystem_name'])
                if master['pki_subsystem'] == "CA":
                    if config.str2bool(master['pki_clone']):
                        # Cloned CA
                        data.setHierarchy("root")
                        data.setIsClone("true")
                        data.setCloneUri(master['pki_clone_uri'])
                        data.setP12File(master['pki_clone_pkcs12_path'])
                        data.setP12Password(
                            sensitive['pki_clone_pkcs12_password'])
                    elif config.str2bool(master['pki_external']):
                        # External CA
                        data.setHierarchy("join")
                        data.setIsClone("false")
                    elif config.str2bool(master['pki_subordinate']):
                        # Subordinate CA
                        data.setHierarchy("join")
                        data.setIsClone("false")
                    else:
                        # PKI CA
                        data.setHierarchy("root")
                        data.setIsClone("false")
                elif master['pki_subsystem'] == "KRA":
                    if config.str2bool(master['pki_clone']):
                        # Cloned KRA
                        data.setIsClone("true")
                        data.setCloneUri(master['pki_clone_uri'])
                        data.setP12File(master['pki_clone_pkcs12_path'])
                        data.setP12Password(
                            sensitive['pki_clone_pkcs12_password'])
                    else:
                        # PKI KRA
                        data.setIsClone("false")
                elif master['pki_subsystem'] == "OCSP":
                    if config.str2bool(master['pki_clone']):
                        # Cloned OCSP
                        data.setIsClone("true")
                        data.setCloneUri(master['pki_clone_uri'])
                        data.setP12File(master['pki_clone_pkcs12_path'])
                        data.setP12Password(
                            sensitive['pki_clone_pkcs12_password'])
                    else:
                        # PKI OCSP
                        data.setIsClone("false")
                elif master['pki_subsystem'] == "TKS":
                    if config.str2bool(master['pki_clone']):
                        # Cloned TKS
                        data.setIsClone("true")
                        data.setCloneUri(master['pki_clone_uri'])
                        data.setP12File(master['pki_clone_pkcs12_path'])
                        data.setP12Password(
                            sensitive['pki_clone_pkcs12_password'])
                    else:
                        # PKI TKS
                        data.setIsClone("false")
            # Security Domain Information
            #
            #     NOTE:  External CA's DO NOT require a security domain
            #
            if master['pki_subsystem'] != "CA" or\
               config.str2bool(master['pki_clone']) or\
               config.str2bool(master['pki_subordinate']):
                # PKI KRA, PKI OCSP, PKI RA, PKI TKS, PKI TPS,
                # CA Clone, KRA Clone, OCSP Clone, TKS Clone, or
                # Subordinate CA
                data.setSecurityDomainType(
                    ConfigurationRequest.EXISTING_DOMAIN)
                data.setSecurityDomainUri(
                    master['pki_security_domain_uri'])
                data.setSecurityDomainUser(
                    master['pki_security_domain_user'])
                data.setSecurityDomainPassword(
                    sensitive['pki_security_domain_password'])
            elif not config.str2bool(master['pki_external']):
                # PKI CA
                data.setSecurityDomainType(
                    ConfigurationRequest.NEW_DOMAIN)
                data.setSecurityDomainName(
                    master['pki_security_domain_name'])
            # Directory Server Information
            if master['pki_subsystem'] != "RA":
                data.setDsHost(master['pki_ds_hostname'])
                data.setDsPort(master['pki_ds_ldap_port'])
                data.setBaseDN(master['pki_ds_base_dn'])
                data.setBindDN(master['pki_ds_bind_dn'])
                data.setDatabase(master['pki_ds_database'])
                data.setBindpwd(sensitive['pki_ds_password'])
                if config.str2bool(master['pki_ds_remove_data']):
                    data.setRemoveData("true")
                else:
                    data.setRemoveData("false")
                if config.str2bool(master['pki_ds_secure_connection']):
                    data.setSecureConn("true")
                else:
                    data.setSecureConn("false")
            # Backup Information
            if master['pki_instance_type'] == "Tomcat":
                if config.str2bool(master['pki_backup_keys']):
                    data.setBackupKeys("true")
                    data.setBackupFile(master['pki_backup_keys_p12'])
                    data.setBackupPassword(
                        sensitive['pki_backup_password'])
                else:
                    data.setBackupKeys("false")
            # Admin Information
            if master['pki_instance_type'] == "Tomcat":
                if not config.str2bool(master['pki_clone']):
                    data.setAdminEmail(master['pki_admin_email'])
                    data.setAdminName(master['pki_admin_name'])
                    data.setAdminPassword(sensitive['pki_admin_password'])
                    data.setAdminProfileID(master['pki_admin_profile_id'])
                    data.setAdminUID(master['pki_admin_uid'])
                    data.setAdminSubjectDN(master['pki_admin_subject_dn'])
                    if master['pki_admin_cert_request_type'] == "crmf":
                        data.setAdminCertRequestType("crmf")
                        if config.str2bool(master['pki_admin_dualkey']):
                            crmf_request = generateCRMFRequest(
                                               token,
                                               master['pki_admin_keysize'],
                                               master['pki_admin_subject_dn'],
                                               "true")
                        else:
                            crmf_request = generateCRMFRequest(
                                               token,
                                               master['pki_admin_keysize'],
                                               master['pki_admin_subject_dn'],
                                               "false")
                        data.setAdminCertRequest(crmf_request)
                    else:
                        javasystem.out.println(log.PKI_JYTHON_CRMF_SUPPORT_ONLY)
                        javasystem.exit(1)
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
            if master['pki_instance_type'] == "Tomcat":
                if not config.str2bool(master['pki_clone']):
                    if master['pki_subsystem'] == "CA":
                        # External CA, Subordinate CA, or PKI CA
                        cert1 = SystemCertData()
                        cert1.setTag(master['pki_ca_signing_tag'])
                        cert1.setKeyAlgorithm(
                            master['pki_ca_signing_key_algorithm'])
                        cert1.setKeySize(master['pki_ca_signing_key_size'])
                        cert1.setKeyType(master['pki_ca_signing_key_type'])
                        cert1.setNickname(master['pki_ca_signing_nickname'])
                        cert1.setSigningAlgorithm(
                            master['pki_ca_signing_signing_algorithm'])
                        cert1.setSubjectDN(master['pki_ca_signing_subject_dn'])
                        cert1.setToken(master['pki_ca_signing_token'])
                        systemCerts.add(cert1)
            # Create 'OCSP Signing Certificate'
            if master['pki_instance_type'] == "Tomcat":
                if not config.str2bool(master['pki_clone']):
                    if master['pki_subsystem'] == "CA" or\
                       master['pki_subsystem'] == "OCSP":
                        # External CA, Subordinate CA, PKI CA, or PKI OCSP
                        cert2 = SystemCertData()
                        cert2.setTag(master['pki_ocsp_signing_tag'])
                        cert2.setKeyAlgorithm(
                            master['pki_ocsp_signing_key_algorithm'])
                        cert2.setKeySize(master['pki_ocsp_signing_key_size'])
                        cert2.setKeyType(master['pki_ocsp_signing_key_type'])
                        cert2.setNickname(master['pki_ocsp_signing_nickname'])
                        cert2.setSigningAlgorithm(
                            master['pki_ocsp_signing_signing_algorithm'])
                        cert2.setSubjectDN(
                            master['pki_ocsp_signing_subject_dn'])
                        cert2.setToken(master['pki_ocsp_signing_token'])
                        systemCerts.add(cert2)
            # Create 'SSL Server Certificate'
            #     PKI RA, PKI TPS,
            #     PKI CA, PKI KRA, PKI OCSP, PKI TKS,
            #     PKI CA CLONE, PKI KRA CLONE, PKI OCSP CLONE, PKI TKS CLONE,
            #     External CA, or Subordinate CA
            cert3 = SystemCertData()
            cert3.setTag(master['pki_ssl_server_tag'])
            cert3.setKeyAlgorithm(master['pki_ssl_server_key_algorithm'])
            cert3.setKeySize(master['pki_ssl_server_key_size'])
            cert3.setKeyType(master['pki_ssl_server_key_type'])
            cert3.setNickname(master['pki_ssl_server_nickname'])
            cert3.setSubjectDN(master['pki_ssl_server_subject_dn'])
            cert3.setToken(master['pki_ssl_server_token'])
            systemCerts.add(cert3)
            # Create 'Subsystem Certificate'
            if master['pki_instance_type'] == "Apache":
                # PKI RA or PKI TPS
                cert4 = SystemCertData()
                cert4.setTag(master['pki_subsystem_tag'])
                cert4.setKeyAlgorithm(master['pki_subsystem_key_algorithm'])
                cert4.setKeySize(master['pki_subsystem_key_size'])
                cert4.setKeyType(master['pki_subsystem_key_type'])
                cert4.setNickname(master['pki_subsystem_nickname'])
                cert4.setSubjectDN(master['pki_subsystem_subject_dn'])
                cert4.setToken(master['pki_subsystem_token'])
                systemCerts.add(cert4)
            elif master['pki_instance_type'] == "Tomcat":
                if not config.str2bool(master['pki_clone']):
                    # PKI CA, PKI KRA, PKI OCSP, PKI TKS,
                    # External CA, or Subordinate CA
                    cert4 = SystemCertData()
                    cert4.setTag(master['pki_subsystem_tag'])
                    cert4.setKeyAlgorithm(master['pki_subsystem_key_algorithm'])
                    cert4.setKeySize(master['pki_subsystem_key_size'])
                    cert4.setKeyType(master['pki_subsystem_key_type'])
                    cert4.setNickname(master['pki_subsystem_nickname'])
                    cert4.setSubjectDN(master['pki_subsystem_subject_dn'])
                    cert4.setToken(master['pki_subsystem_token'])
                    systemCerts.add(cert4)
            # Create 'Audit Signing Certificate'
            if master['pki_instance_type'] == "Apache":
                if master['pki_subsystem'] != "RA":
                    # PKI TPS
                    cert5 = SystemCertData()
                    cert5.setTag(master['pki_audit_signing_tag'])
                    cert5.setKeyAlgorithm(
                        master['pki_audit_signing_key_algorithm'])
                    cert5.setKeySize(master['pki_audit_signing_key_size'])
                    cert5.setKeyType(master['pki_audit_signing_key_type'])
                    cert5.setNickname(master['pki_audit_signing_nickname'])
                    cert5.setKeyAlgorithm(
                        master['pki_audit_signing_signing_algorithm'])
                    cert5.setSubjectDN(master['pki_audit_signing_subject_dn'])
                    cert5.setToken(master['pki_audit_signing_token'])
                    systemCerts.add(cert5)
            elif master['pki_instance_type'] == "Tomcat":
                if not config.str2bool(master['pki_clone']):
                    # PKI CA, PKI KRA, PKI OCSP, PKI TKS,
                    # External CA, or Subordinate CA
                    cert5 = SystemCertData()
                    cert5.setTag(master['pki_audit_signing_tag'])
                    cert5.setKeyAlgorithm(
                        master['pki_audit_signing_key_algorithm'])
                    cert5.setKeySize(master['pki_audit_signing_key_size'])
                    cert5.setKeyType(master['pki_audit_signing_key_type'])
                    cert5.setNickname(master['pki_audit_signing_nickname'])
                    cert5.setKeyAlgorithm(
                        master['pki_audit_signing_signing_algorithm'])
                    cert5.setSubjectDN(master['pki_audit_signing_subject_dn'])
                    cert5.setToken(master['pki_audit_signing_token'])
                    systemCerts.add(cert5)
            # Create 'DRM Transport Certificate'
            if master['pki_instance_type'] == "Tomcat":
                if not config.str2bool(master['pki_clone']):
                    if master['pki_subsystem'] == "KRA":
                        # PKI KRA
                        cert6 = SystemCertData()
                        cert6.setTag(master['pki_transport_tag'])
                        cert6.setKeyAlgorithm(
                            master['pki_transport_key_algorithm'])
                        cert6.setKeySize(master['pki_transport_key_size'])
                        cert6.setKeyType(master['pki_transport_key_type'])
                        cert6.setNickname(master['pki_transport_nickname'])
                        cert6.setKeyAlgorithm(
                            master['pki_transport_signing_algorithm'])
                        cert6.setSubjectDN(master['pki_transport_subject_dn'])
                        cert6.setToken(master['pki_transport_token'])
                        systemCerts.add(cert6)
            # Create 'DRM Storage Certificate'
            if master['pki_instance_type'] == "Tomcat":
                if not config.str2bool(master['pki_clone']):
                    if master['pki_subsystem'] == "KRA":
                        # PKI KRA
                        cert7 = SystemCertData()
                        cert7.setTag(master['pki_storage_tag'])
                        cert7.setKeyAlgorithm(
                            master['pki_storage_key_algorithm'])
                        cert7.setKeySize(master['pki_storage_key_size'])
                        cert7.setKeyType(master['pki_storage_key_type'])
                        cert7.setNickname(master['pki_storage_nickname'])
                        cert7.setKeyAlgorithm(
                            master['pki_storage_signing_algorithm'])
                        cert7.setSubjectDN(master['pki_storage_subject_dn'])
                        cert7.setToken(master['pki_storage_token'])
                        systemCerts.add(cert7)
            # Create system certs
            data.setSystemCerts(systemCerts)
        return data

    def configure_pki_data(self, data, master, sensitive):
        if master['pki_jython_log_level'] >= config.PKI_JYTHON_INFO_LOG_LEVEL:
            print "%s %s '%s'" %\
                  (log.PKI_JYTHON_INDENTATION_2,
                   log.PKI_JYTHON_CONFIGURING_PKI_DATA,
                   master['pki_subsystem'])
        if not master['pki_dry_run_flag']:
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
                    javasystem.out.println(log.PKI_JYTHON_ADMIN_CERT_SAVE +\
                                           " " + "'" + admin_cert_file + "'")
                    FILE = open(admin_cert_file, "w")
                    FILE.write(admin_cert)
                    FILE.close()
                    # Since Jython runs under Java, it does NOT support the
                    # following operating system specific command:
                    #
                    #     os.chmod(
                    #         admin_cert_file,
                    #         config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS)
                    #
                    # Emulate it with a system call.
                    command = "chmod" + " " + "660" + " " + admin_cert_file
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
                              "-a" + " " +\
                              "-i" + " " +\
                              admin_cert_file
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
