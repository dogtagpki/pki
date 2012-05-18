#!/usr/bin/jython

# System Java Imports
from java.io import BufferedReader
from java.io import ByteArrayInputStream
from java.io import FileReader
from java.io import IOException
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
import os
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
jarLoad.addFile("/usr/share/java/apache-commons-cli.jar")
#     Resteasy Jars
jarLoad.addFile("/usr/share/java/glassfish-jaxb/jaxb-impl.jar")
jarLoad.addFile("/usr/share/java/resteasy/jaxrs-api.jar")
jarLoad.addFile("/usr/share/java/resteasy/resteasy-jaxb-provider.jar")
jarLoad.addFile("/usr/share/java/resteasy/resteasy-jaxrs.jar")
jarLoad.addFile("/usr/share/java/resteasy/resteasy-jettison-provider.jar")
jarLoad.addFile("/usr/share/java/scannotation.jar")
#     PKI Jars
jarLoad.addFile("/usr/share/java/pki/pki-cms.jar")
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
from com.netscape.cms.servlet.csadmin import ConfigurationRESTClient
from com.netscape.cms.servlet.csadmin.model import CertData
from com.netscape.cms.servlet.csadmin.model import ConfigurationData
from com.netscape.cms.servlet.csadmin.model import ConfigurationResponseData
from com.netscape.cmsutil.util import Utils
from netscape.security.x509 import X500Name


# PKI Python Imports
import pkiconfig as config
import pkimessages as log


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
            javasystem.out.println("INITIALIZATION ERROR: " + str(e))
            javasystem.exit(1)

    def log_into_token(self, pki_database_path, password_conf,
                       pki_dry_run_flag, log_level):
        try:
            if log_level >= config.PKI_JYTHON_INFO_LOG_LEVEL:
                print "%s %s '%s'" %\
                      (log.PKI_JYTHON_INDENTATION_2,
                       log.PKI_JYTHON_LOG_INTO_TOKEN,
                       pki_database_path)
            if not pki_dry_run_flag:
                manager = CryptoManager.getInstance()
                token = manager.getInternalKeyStorageToken()
                # Retrieve 'token_pwd' from 'password_conf'
                #
                #     NOTE:  For now, ONLY read the first line
                #            (which contains the password)
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
                    javasystem.out.println("login Exception: " + str(e))
                    if not token.isLoggedIn():
                        token.initPassword(password, password)
        except Exception, e:
            javasystem.out.println("Exception in logging into token: " +\
                                   str(e))
            javasystem.exit(1)

# PKI Deployment Jython Class Instances
security_databases = security_databases()
