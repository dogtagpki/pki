#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: ExternalCA Supporting functions
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   This is the library for ExternalCA sypporting class and Functions.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Geetika Kapoor <gkapoor@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2018 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import commands
import ConfigParser
import logging
import os
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

log = logging.getLogger(__name__)


if os.path.isfile('/tmp/test_dir/constants.py'):
    import sys
    sys.path.append('/tmp/test_dir')
    import constants

class Config(object):
    '''
    This class is written to create a configuration let it be CA/KRA/OCSP/TPS/TKS
    or LDAP.If there is a standard section as "DEFAULT" use the function default
    as written else try to use section function.
    '''

    def add_default(self, conf, **kwargs):
        if kwargs.keys() is not None:
            config = ConfigParser.RawConfigParser()
            config.optionxform = str
            for key in kwargs.iterkeys():
                config.set('DEFAULT', key, kwargs[key])
            with open(conf, 'w') as fileobj:
                config.write(fileobj)

    def add_section(self, conf, section, **kwargs):
        if kwargs.keys() is not None:
            config = ConfigParser.RawConfigParser()
            config.optionxform = str
            config.add_section('{}'.format(section))
            for key in kwargs.iterkeys():
                config.set('{}'.format(section), key, kwargs[key])
            with open(conf, 'a') as fileobj:
                config.write(fileobj)

class pki_externalca_common(object):
    '''
    This setup will use DogtagCA as an external signing CA.
    One Dogtag CA which acts as a RootCA will sign certificate
    For another Dogtag CA
    This is the main class which
    '''

    def __init__(self, **kwargs):
        self.ca_http_port = kwargs['ca_http_port'] if 'ca_http_port' in kwargs.keys() else constants.CA_HTTP_PORT
        self.ca_protocol = kwargs['ca_protocol'] if 'ca_protocol' in kwargs.keys() else constants.PROTOCOL_UNSECURE
        self.profile = kwargs['profile'] if 'profile' in kwargs.keys() else 'caCACert'
        self.ca_signing_csr = kwargs['ca_signing_csr'] \
            if 'ca_signing_csr' in kwargs.keys() else '/tmp/ca_signing.csr'
        self.ca_signing_crt = kwargs['ca_signing_crt'] \
            if 'ca_signing_crt' in kwargs.keys() else '/tmp/ca_signing.crt'
        self.rootca_signing_crt = kwargs['rootca_signing_crt'] \
            if 'rootca_signing_crt' in kwargs.keys() else '/tmp/external.crt'
        self.trust = kwargs['trust'] if 'trust' in kwargs.keys() else 'CT,C,C'
        self.ca_cert_nick = kwargs['ca_cert_nick'] \
            if 'ca_cert_nick' in kwargs.keys() else constants.CA_ADMIN_NICK
        self.cacert_nick = kwargs['cacert_nick'] if 'cacert_nick' in kwargs.keys() else 'testuser'
        self.rootca_nick = kwargs['rootca_nick'] if 'rootca_nick' in kwargs.keys() else 'RootCA'
        self.nssdb = kwargs['nssdb'] if 'nssdb' in kwargs.keys() else '/opt/pkitest/certdb'
        self.config_step1 = kwargs['config_step1'] \
            if 'config_step1' in kwargs.keys() else '/tmp/config_step1.cfg'
        self.config_step2 = kwargs['config_step2'] \
            if 'config_step2' in kwargs.keys() else '/tmp/config_step2.cfg'
        self.subsystem = kwargs['subsystem'] if 'subsystem' in kwargs.keys() else 'CA'
        self.passwd = kwargs['passwd'] if 'passwd' in kwargs.keys() else 'SECret.123'
        self.pass_file = kwargs['pass_file'] if 'pass_file' in kwargs.keys() else '/tmp/pass.txt'
        self.instance_name = kwargs['instance_name'] if 'instance_name' in kwargs.keys() else 'pki-tomcat'
        self.externalca_port = kwargs['externalca_port'] if 'externalca_port' in kwargs.keys() else '8080'

    def create_nssdb(self, ansible_module):
        '''
        Create nssdb if doesn't exist
        '''
        command = ['mkdir -p %s' %(self.nssdb), 'echo %s > /tmp/pass.txt' %(self.passwd),
                    'certutil -N -d %s -f %s' % (self.nssdb, self.pass_file)]
        for x in command:
            output = ansible_module.shell(x)
            log.info("Create nssdb: %s",x)
        return map(str,[output[x]['cmd'] for x in output.iterkeys()])[0]

    def generate_csr(self, ansible_module):
        '''
        Generate csr using step1 installation.
        '''
        cmd = 'pkispawn -f %s -s %s -v' % (self.config_step1, self.subsystem)
        try:
            log.info("Running pkispawn command : %s", cmd)
            pkispawn_output = ansible_module.command(cmd)
            assert "certificate has been generated" in map(str,[pkispawn_output[x]['stdout']
                                                                               for x in pkispawn_output.iterkeys()])[0] \
                   and map(int,[pkispawn_output[x]['rc'] for x in pkispawn_output.iterkeys()])[0] == 0
        except AssertionError:
            raise Exception("Pkispawn step1 csr creation failure")
        else:
            return map(str,[pkispawn_output[x]['stdout'] for x in pkispawn_output.iterkeys()])[0]

    def install_externalca(self, ansible_module):
        '''
        Install and configure External CA using step2.

        '''
        cmd = 'pkispawn -f %s -s %s -v' % (self.config_step2, self.subsystem)
        try:
            log.info("Running pkispawn step 2 and create ExternalCA: %s", cmd)
            pkispawn_output = ansible_module.command(cmd)
            assert "Administrator's PKCS #12 file" in map(str,[pkispawn_output[x]['stdout'] \
                                                      for x in pkispawn_output.iterkeys()])[0] \
                   and map(int,[pkispawn_output[x]['rc'] for x in pkispawn_output.iterkeys()])[0] == 0
        except Exception:
            raise Exception(map(str,[pkispawn_output[x]['stdout'] for x in pkispawn_output.iterkeys()])[0])
        else:
            return map(str,[pkispawn_output[x]['stdout'] for x in pkispawn_output.iterkeys()])[0]

    def importp12_externalca(self, ansible_module, p12file="/root/.dogtag/pki-tomcat/ca_admin_cert.p12"):
        '''
        Import ExternalCA certificate to nssdb
        '''
        cmd = 'pk12util -d %s -i %s -W %s -K %s' %(self.nssdb, p12file, self.passwd, self.passwd)
        try:
            output = ansible_module.command(cmd)
            log.info("Importing ExtrenalCA certificate to nssdb : %s", cmd)
            assert "pk12util: PKCS12 IMPORT SUCCESSFUL" in map(str,[output[x]['stdout'] \
                                                                    for x in output.iterkeys()])[0] \
                   and map(int,[output[x]['rc'] for x in output.iterkeys()])[0] == 0
        except Exception:
            raise Exception("Return code is: %d , which is incorrect" %(map(int,[output[x]['rc'] for x
                                                                                 in output.iterkeys()])[0]))
        else:
            return map(str,[output[x]['stdout'] for x in output.iterkeys()])[0]

    def find(self, out, search, key='stdout'):
        '''
        This function will look for any keyword in either stdout or stderr
        in  ansible dict output.
        '''
        for values in out.itervalues():
            for items in [x.strip(' ') for x in values[key].splitlines()]:
                if items.startswith('{}'.format(search)):
                    req = items.strip('{}'.format(search))
                    return str(req)

class pki_externalca(pki_externalca_common):
    '''
    This has functions meant for only externalCA install using pki
    '''

    def extract_signingcrt(self, ansible_module, issuer='system', name='"CA Signing Certificate"' ):

        log.info("Extracting ExternalCA certificate serial number")
        cmd = 'pki -p %s -P %s -d %s -c %s -n "%s" --ignore-cert-status ' \
              'UNTRUSTED_ISSUER ca-cert-find --issuedBy %s --name %s'\
              %(self.ca_http_port, self.ca_protocol, self.nssdb, self.passwd, self.ca_cert_nick, issuer, name)
        try:
            output = ansible_module.command(cmd)
            assert map(int,[output[x]['rc'] for x in output.iterkeys()])[0] == 0
        except AssertionError:
            raise Exception("Dogtagpki:Unable to get CA Signing certificate")
        else:
            return output

    def submit_csr(self, ansible_module):

        log.info("Submit csr to the RootCA: Dogtagpki")
        cmd = 'pki -p %s -P %s ca-cert-request-submit --profile %s --csr-file %s' \
              %(self.ca_http_port, self.ca_protocol, self.profile, self.ca_signing_csr)
        try:
            output = ansible_module.command(cmd)
            assert map(int,[output[x]['rc'] for x in output.iterkeys()])[0] == 0
        except AssertionError:
            raise Exception("Dogtagpki: Unable to send successful csr request to RootCA")
        else:
            return output

    def approve_csr(self, ansible_module, request_id):
        cmd = 'pki -p %s -P %s -d %s -c %s -n "%s" --ignore-cert-status UNTRUSTED_ISSUER ca-cert-request-review %s --action approve' \
              %(self.ca_http_port, self.ca_protocol, self.nssdb, self.passwd, self.ca_cert_nick, request_id)
        try:
            approve_csr = ansible_module.shell(cmd)
            assert map(int,[approve_csr[x]['rc'] for x in approve_csr.iterkeys()])[0] == 0
        except AssertionError:
            raise Exception("Dogtagpki: Unable to send successful csr request to RootCA")
        else:
            return approve_csr

    def extract_external_ca_crt(self, ansible_module, cert_id, import_nick, cert_file):

        log.info("Extracting ExternalCA certificate")
        cmd = 'pki -p %s -P %s -d %s -c %s -n "%s" --ignore-cert-status ' \
              'UNTRUSTED_ISSUER client-cert-import %s --serial %s --trust %s'\
              %(self.ca_http_port, self.ca_protocol, self.nssdb, self.passwd, self.ca_cert_nick, import_nick, cert_id, self.trust)
        ansible_module.command(cmd)
        try:
            output = ansible_module.shell('certutil -L -d %s -n %s -a > %s' %(self.nssdb, import_nick,
                                                                              cert_file))
            assert map(int,[output[x]['rc'] for x in output.iterkeys()])[0] == 0
        except AssertionError:
            raise Exception("Dogtagpki: Unable to import  certificate in nssdb")
        else:
            return map(int,[output[x]['rc'] for x in output.iterkeys()])[0]


    def submit_usercsr(self, ansible_module, subject_dn='"uid=testusercert"'):

        log.info("Submit user certificate request : Dogtagpki")
        try:
            output = ansible_module.command('pki -p %s -P %s -d %s -c %s client-cert-request %s ' %(self.externalca_port,
                                                                                              self.ca_protocol,self.nssdb, self.passwd, subject_dn))
            assert map(int,[output[x]['rc'] for x in output.iterkeys()])[0] == 0
        except AssertionError:
            raise Exception("Dogtagpki: Unable to send successful csr request to ExternalCA")
        else:
            return output

    def approve_usercsr(self, ansible_module, request_id):
        cmd = 'pki -p %s -P %s -d %s -c %s -n "%s" cert-request-review %s --action approve' \
              %(self.externalca_port, self.ca_protocol, self.nssdb, self.passwd, constants.CA_ADMIN_USERNAME, request_id)
        try:
            approve_csr = ansible_module.command(cmd)
            assert map(int,[approve_csr[x]['rc'] for x in approve_csr.iterkeys()])[0] == 0
        except AssertionError:
            raise Exception("Dogtagpki: Unable to send successful csr request to ExternalCA")
        else:
            return approve_csr

class nssdb_externalca(pki_externalca_common):
    '''
    This setup will use CA created using nssdb as an external signing CA.
    NssDB CA which acts as a RootCA will sign certificate
    for a Dogtag CA
    '''

    def create_rootca_nssdb(self, ansible_module, rootca_skid="0xf738a050e0ff8e1078c8fd7ac75ff0a2ba397072"):
        ansible_module.shell('openssl rand -out noise.bin 2048')
        ocsp = "http://localhost:8080/ca/ocsp"
        cmd = 'echo -e "y\n\ny\ny\n%s\n\n\n\n%s\n\n2\n7\n%s\n\n\n\n" | \
 certutil -S \
 -x \
 -d %s \
 -f %s \
 -z noise.bin \
 -n "RootCA" \
 -s "CN=Root CA Signing Certificate,O=ROOT" \
 -t "CT,C,C" \
 -m $RANDOM\
 -k rsa \
 -g 2048 \
 -Z SHA256 \
 -2 \
 -3 \
 --extAIA \
 --extSKID \
 --keyUsage critical,certSigning,crlSigning,digitalSignature,nonRepudiation' %(rootca_skid, rootca_skid, ocsp,
                                                                               self.nssdb, self.pass_file )
        try:
            import_crt = ansible_module.shell(cmd)
            log.info("Creating RootCA using nssdb and Certutil")
            ansible_module.shell('certutil -L -d %s -n %s -a > %s' %
                                               (self.nssdb, self.rootca_nick, self.rootca_signing_crt))
            assert "Generating key" in map(str,[import_crt[x]['stderr_lines'] for x in import_crt.iterkeys()])[0]
        except AssertionError:
            raise Exception(map(str,[import_crt[x]['stderr_lines'] for x in import_crt.iterkeys()])[0])
        else:
            return map(int, [import_crt[x]['rc'] for x in import_crt.iterkeys()])[0]

    def create_externalca_cert_skid(self, ansible_module, ca_skid="0x110b97b22f78e85e0b3de580a893a6e01dddf2c4",
                                    rootca_skid="0xf738a050e0ff8e1078c8fd7ac75ff0a2ba397072"):
        ansible_module.shell('openssl rand -out noise.bin 2048')
        ocsp = "http://localhost:8080/ca/ocsp"
        cmd = 'echo -e "y\n\ny\ny\n%s\n\n\n\n%s\n\n2\n7\n%s\n\n\n\n" | \
 certutil -C \
 -d %s \
 -f %s \
 -m $RANDOM \
 -a \
 -i %s \
 -o %s \
 -c "RootCA" \
 -2 \
 -3 \
 --extAIA \
 --extSKID \
 --keyUsage critical,certSigning,crlSigning,digitalSignature,nonRepudiation' %(rootca_skid, ca_skid, ocsp, self.nssdb,
                                                                               self.pass_file, self.ca_signing_csr,
                                                                               self.ca_signing_crt)
        try:
            import_crt = ansible_module.shell(cmd)
            log.info("Sign csr using External RootCA and generate ca_signing_certificate")
            assert "certutil" not in map(str,[import_crt[x]['stderr_lines'] for x in
                                                                 import_crt.iterkeys()])[0] and \
                   map(int,[import_crt[x]['rc'] for x in import_crt.iterkeys()])[0] == 0
        except AssertionError:
            raise Exception(map(str,[import_crt[x]['stderr'] for x in import_crt.iterkeys()])[0])
        else:
            return map(int, [import_crt[x]['rc'] for x in import_crt.iterkeys()])[0]

    def create_externalca_cert_noskid(self, ansible_module):
        ansible_module.shell('openssl rand -out noise.bin 2048')
        ocsp = "http://localhost:8080/ca/ocsp"
        cmd = 'echo -e "0\n1\n5\n6\n9\ny\ny\n\ny\n" | \
 certutil -C \
 -d %s  \
 -f %s \
 -m $RANDOM \
 -a -i %s\
 -o %s \
 -c "RootCA" \
 -1 -2' %(self.nssdb, self.pass_file, self.ca_signing_csr, self.ca_signing_crt )
        import_crt = ansible_module.shell(cmd)
        return import_crt

class openssl_externalca(pki_externalca_common):

    def __init__(self, **kwargs):
        pki_externalca_common.__init__(self, **kwargs)
        self.extra_args = kwargs['extra_args'] if 'extra_args' in kwargs.keys() else ''
        self.keysize = kwargs['keysize'] if 'keysize' in kwargs.keys() else '2048'
        self.__key = kwargs['key'] if 'key' in kwargs.keys() else '/tmp/' + str(uuid.uuid4()) + '.key'
        self.csr = kwargs['csr'] if 'csr' in kwargs.keys() else '/tmp/csr.pem'
        self.validity = kwargs['validity'] if 'validity' in kwargs.keys() else '365'


    def __generate_pkey(self,ansible_module):

        log.info("Generate Private key")
        try:
            output = ansible_module.command("openssl genrsa -out {} 2048".format(self.__key))
            assert "Generating RSA private key" in map(str,[output[x]['stderr']
                                                                               for x in output.iterkeys()])[0] \
                   and map(int,[output[x]['rc'] for x in output.iterkeys()])[0] == 0
        except AssertionError:
            raise Exception("Unable to generate private key")
        else:
            log.info("Private key is generated Successfully")

    def generate_opensslcsr(self, ansible_module, cert_subject = '"/CN=CA Certificate/O=Example"'):

        log.info("Generating Csr using openssl mechanism")
        self.__generate_pkey(ansible_module)
        try:
            output = ansible_module.command("openssl req -key {} -nodes -new -out {} -subj {} -days {}"\
            .format(self.__key, self.csr, cert_subject, self.validity))
            assert map(int,[output[x]['rc'] for x in output.iterkeys()])[0] == 0
        except AssertionError:
            raise Exception("Unable to generate csr file")

    def generate_cacert(self, ansible_module):

        log.info("Generate CA self signed certificate")
        try:
            output = ansible_module.command("openssl req -x509 -newkey rsa:2048 -keyout {} -nodes -new -out {} "
                                        "-subj '/CN=CA Certificate/O=Example' -days {}"\
            .format(self.__key, self.rootca_signing_crt , self.validity))
            assert map(int,[output[x]['rc'] for x in output.iterkeys()])[0] == 0
        except AssertionError:
            raise Exception("Unable to generate Certificate file")

    def issue_cert(self,ansible_module):

        log.info("Issue certificate from openssl CA")
        try:
            output = ansible_module.command("openssl x509 -req -in {} -CA {} -CAkey {} -CAcreateserial -out {}"
            .format(self.ca_signing_csr, self.rootca_signing_crt, self.__key, self.ca_signing_crt))
            assert map(int,[output[x]['rc'] for x in output.iterkeys()])[0] == 0
        except AssertionError:
            raise Exception("Unable to generate Certificate file")

    def verify_cacert(self,ansible_module):
        log.info("Verify: Certificate created using openssl")
        try:
            output = ansible_module.command("openssl x509 -text -noout -in {}".format(self.ca_signing_crt))
            assert map(int,[output[x]['rc'] for x in output.iterkeys()])[0] == 0
        except AssertionError:
            raise Exception("Certificate verification Failed")

class ExternalcaVerify(pki_externalca_common):
    '''
    This class is written to cover functions that are needed for externalCA verification purpose.
    This can be used commonly.
    '''
    def verify_externalca_causers(self, ansible_module):
        '''
        Verify once eternalCA is installed to make sure it is up.
        '''
        cmd = 'pki  -d %s -c %s -n "caadmin" --ignore-cert-status UNTRUSTED_ISSUER,UNKNOWN_ISSUER ca-user-find' \
              % (self.nssdb, self.passwd)
        try:
            output = ansible_module.command(cmd)
            log.info("Verify ExternalCA is installed : %s", cmd)
            assert "Number of entries returned 3" in map(str,[output[x]['stdout'] for x in output.iterkeys()])[0]
        except Exception:
            raise Exception("Return code is: %d , which is incorrect" %(map(int,[output[x]['rc'] for x
                                                                                 in output.iterkeys()])[0]))
        else:
            return map(str,[output[x]['stdout_lines'] for x in output.iterkeys()])[0]


    def get_skid(self,ansible_module, certificate_file):

        cert = ansible_module.command('cat {}'.format(certificate_file))
        cert = x509.load_pem_x509_certificate(map(str,[cert[x]['stdout'] for x in cert.iterkeys()])[0], default_backend())
        skid = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
        return skid

    def get_akid(self, ansible_module, certificate_file):

        cert = ansible_module.command('cat {}'.format(certificate_file))
        cert = x509.load_pem_x509_certificate(map(str,[cert[x]['stdout'] for x in cert.iterkeys()])[0], default_backend())
        akid = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier
        return akid

