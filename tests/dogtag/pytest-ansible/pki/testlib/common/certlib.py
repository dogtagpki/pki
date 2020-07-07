# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2017 Red Hat, Inc. All rights reserved.
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

import logging
import os
import sys
from datetime import datetime
from subprocess import CalledProcessError

import OpenSSL.crypto as crypto
import pytest

from pki.testlib.common.exceptions import PkiLibException
from pki.testlib.common.profile import Setup
from pki.testlib.common.utils import UserOperations, ProfileOperations

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
if os.path.isfile('/tmp/test_dir/constants.py'):
    sys.path.append('/tmp/test_dir')
    import constants

userop = UserOperations(nssdb=constants.NSSDB)
profileop = ProfileOperations()


class CertSetup(object):
    """
    This class contains methods to create a certdb, adding certs to db,
    create role users
    """

    def __init__(self, **kwargs):
        self.nssdb = kwargs.get('nssdb', constants.NSSDB)
        self.db_pass = kwargs.get('db_pass', constants.CLIENT_DATABASE_PASSWORD)
        self.host = kwargs.get('host', constants.MASTER_HOSTNAME)
        self.protocol = kwargs.get('protocol', 'http')
        self.port = kwargs.get('port', constants.CA_HTTP_PORT)
        self.nick = kwargs.get('nick', constants.CA_ADMIN_NICK)

    def pkcs12_path(self, subsystem='ca'):
        """
        Returns pkcs12 path
        """
        s = subsystem.lower()
        if s in ['ca', 'kra', 'ocsp', 'tks', 'tps']:
            path = eval("constants.{}_CLIENT_DIR".format(s.upper())) + "/{}_admin_cert.p12".format(s)
            return path

    def create_certdb(self, ansible_module):
        """
        Creates a certdb. Default location is /opt/pki/certdb which can be overridden
        """
        client_init = 'pki -d {} -c {} client-init'.format(self.nssdb, self.db_pass)
        create_cert_db = ansible_module.shell(client_init)
        for result in create_cert_db.values():
            if 'Security database already exists' in result['stdout']:
                raise Exception('Security Database already Exists', '255')
            else:
                #                assert "Client initialized" in result['stdout']
                log.info("Created certdb {}".format(self.nssdb))

    def import_admin_p12(self, ansible_module, subsystem):
        """
        Import subsystem admin p12 to certdb
        """
        pkcs12path = self.pkcs12_path(subsystem)
        import_admin_p12 = ansible_module.pki(cli='client-cert-import',
                                              nssdb=self.nssdb,
                                              dbpassword=self.db_pass,
                                              port=self.port,
                                              extra_args='--pkcs12 {} --pkcs12-password '
                                                         '{}'.format(pkcs12path,
                                                                     constants.CLIENT_PKCS12_PASSWORD))
        for result in import_admin_p12.values():
            print(result)
            assert "Imported certificate" in result['stdout']
            log.info("Imported {} admin cert, {}".format(subsystem, pkcs12path))

    def import_ca_cert(self, ansible_module):
        """
        Import CA cert to certdb
        """
        import_ca_cert = ansible_module.pki(cli='client-cert-import',
                                            nssdb=self.nssdb,
                                            dbpassword=self.db_pass,
                                            port=constants.CA_HTTP_PORT,
                                            certnick="RootCA",
                                            extra_args="--ca-server")
        for result in import_ca_cert.values():
            print(result)
#            assert "Imported certificate \"RootCA\"" in result['stdout']
            log.info("Imported CA cert")

    def setup_role_users(self, ansible_module, subsystem, duration='day'):
        """
        Create various role users needed for cli tests
        """
        role_user_dict = {'CA': ['Administrators', 'Auditors', 'Certificate Manager Agents'],
                          'KRA': ['Administrators', 'Auditors', 'Data Recovery Manager Agents'],
                          'OCSP': ['Administrators', 'Auditors', 'Online Certificate Status Manager Agents'],
                          'TKS': ['Administrators', 'Auditors', 'Token Key Service Manager Agents'],
                          'TPS': ['TPS Agents', 'Administrators', 'TPS Auditors']}  # 'UnPrivileged'
        user_identifier = ['E', 'R', 'V']  # 'UnTrusted'
        roles = ['Agent', 'Admin', 'Audit']  # 'UnPrivileged'
        common_groups = role_user_dict[subsystem.upper()]

        # create a group UnPrivileged
        # unprivileged_group = ansible_module.pki(cli="{}-group-add".format(subsystem),
        #                                         nssdb=self.nssdb,
        #                                         dbpassword=self.db_pass,
        #                                         port=self.port,
        #                                         certnick=self.nick,
        #                                         extra_args="UnPrivileged")

        if subsystem.lower() == 'ca':
            self.add_expired_profile_to_ca(ansible_module, duration)

        for role in roles:
            for u_id in user_identifier:
                user_name = "{}_{}{}".format(subsystem.upper(), role, u_id)
                group_name = [i for i in common_groups if role in i][0]
                if self.create_role_user(ansible_module, subsystem, user_name, group_name):
                    subject_dn = "UID={},E={}@example.org,CN={},OU=IDMQE,C=US".format(user_name, user_name, user_name)
                    if u_id is 'E':
                        cert_serial = userop.process_certificate_request(ansible_module, subject=subject_dn,
                                                                         profile='caAgentFoobar')
                    else:
                        cert_serial = userop.process_certificate_request(ansible_module, subject=subject_dn,
                                                                         profile='caUserCert')
                    if u_id is 'R':
                        userop.revoke_certificate(ansible_module, cert_serial, 'Key_Compromise')

                    added = userop.add_cert_to_user(ansible_module, user_name, cert_serial, subsystem=subsystem,
                                                    remove_cert=False)
                    if not added:
                        return False
                else:
                    return False
        return True

    def create_role_user(self, ansible_module, subsystem, userid, groupid):
        ''' create role user for specific subsystem
        :param str user_nick: Nickname of the user using which role user should be added
            if None, it uses Admin cert
        :param str subsystem: Subsystem to which user should be added
        :param str userid: User id to be added
        :param str groupid: Group to which the userid should be member of
        :Returns None
        :raises PkiLibException if adding the user or making the user member of
            of the group fails
        '''
        added = userop.add_user(ansible_module, 'add', userid=userid, user_name=userid, subsystem=subsystem)
        if added:
            log.info("Added user {}".format(userid))
        else:
            log.error("Failed to add user {}".format(userid))

        try:
            ansible_module.pki(cli="{}-group-member-add".format(subsystem),
                               nssdb=self.nssdb,
                               dbpassword=self.db_pass,
                               port=self.port,
                               certnick=self.nick,
                               extra_args="'{}' {}".format(groupid, userid))
        except CalledProcessError as err:
            raise PkiLibException('Unable to add %s to role %s' % (userid, groupid), err.returncode)
        else:
            log.info("Successfully added user %s to role %s" % (userid, groupid))
            return True

    def import_cert_to_certdb(self, ansible_module, cert_serial_number, nickname):
        ''' Import certificate to certdb
        :param str cert_serial_number: serial Number of the cert
        :param str nickname: nickname to be used to import the cert to certdb
        :Returns None
        :Raises PkiLibException if importing the cert fails
        '''
        try:
            import_to_certdb = ansible_module.pki(cli="client-cert-import",
                                                  nssdb=self.nssdb,
                                                  dbpassword=self.db_pass,
                                                  hostname=constants.MASTER_HOSTNAME,
                                                  port=constants.CA_HTTP_PORT,
                                                  certnick=nickname,
                                                  extra_args="--serial {}".format(cert_serial_number))
        except CalledProcessError as err:
            raise PkiLibException('Unable to import cert %s to certdb %s' % (
                cert_serial_number, constants.NSSDB), err.returncode)
        else:
            log.info("Successfully added cert %s to certdb %s with nick %s" % (
                cert_serial_number, constants.NSSDB, nickname))
            result = None
            for result in import_to_certdb.values():
                pass
            return [result['rc'], result['stdout']]

    def add_expired_profile_to_ca(self, ansible_module, duration):
        profileid = 'caAgentFoobar'
        # create a custom profile for Agent
        p_obj = Setup(profile_type='user', profile_id=profileid)
        profile_params = {'ProfileName': '%s Enrollment Profile' % (profileid),
                          'notBefore': '2',
                          'notAfter': '2',
                          'ValidFor': '1',
                          'rangeunit': duration,
                          'MaxValidity': '15'}

        output_list = p_obj.create_profile(profile_params)
        try:
            self.add_new_profile(ansible_module, profileid, output_list[0])
        except PkiLibException as err:
            pytest.xfail("Unable to add new profile, failed with error: %s" % (err.msg))
        # Enable the profile Using Agent cert
        try:
            self.enable_profile(ansible_module, profileid)
        except PkiLibException as err:
            pytest.xfail("Unable to enable profile, failed with error: %s" % (err.msg))

    def add_new_profile(self, ansible_module, profile_id, profile_xml, user_nick=None):
        ''' Add a new profile xml as user_nick
        :param str profile_id: Profile Name
        :param str profile_xml: Path of the profile xml to be added
        :param str user_nick: Certificate Nick to be used to submit the request, if none, CA Admin
            cert will be used to submit the request
        :Returns None
        :Raises PkiLibException if profile could not be added
        '''
        if user_nick is None:
            user_nick = self.nick
        destination_profile_path = "/tmp/new-{}.xml".format(profile_id)
        try:
            file_contents = None
            with open(profile_xml) as infile:
                file_contents = infile.read()
            ansible_module.copy(content=file_contents, dest=destination_profile_path)
        except IOError as err:
            raise PkiLibException("Unable to copy file")
        try:
            return profileop.add_profile(ansible_module, profile_name=profile_id, profile_path=destination_profile_path)
        except CalledProcessError as err:
            raise PkiLibException('Unable to add profile :%s' % (profile_xml), err.returncode)

    def enable_profile(self, ansible_module, profile_id):
        ''' Enable a profile as user_nick
        :param str profile_id: Profile Name
        :Returns True if success else False
        '''
        return profileop.enable_profile(ansible_module, profile_name=profile_id)

    def cert_show(self, ansible_module, cert_serial_no, ca_http_port=None):
        ''' Run cert show on cert serial number
        :param str cert_serial_no: Certficiate Serial Number
        :Returns None
        :Raises PkiLibException if profile could not be enabled
        '''
        if ca_http_port is None:
            ca_http_port = constants.CA_HTTP_PORT

        output_file = "%s/%s.pem" % (constants.NSSDB, cert_serial_no)
        try:
            cert_show = ansible_module.pki(
                cli="cert-show",
                nssdb=self.nssdb,
                dbpassword=self.db_pass,
                hostname=self.host,
                port=self.port,
                certnick="'{}'".format(constants.CA_ADMIN_NICK),
                extra_args="{} --pretty --output {}".format(cert_serial_no, output_file)
            )
        except CalledProcessError as err:
            raise PkiLibException('Unable run cert-show on serial number :%s' % (cert_serial_no),
                                  err.returncode)
        else:
            output_text = None
            for result in cert_show.values():
                output_text = result['stdout']
            return (output_text, output_file)

    def cert_attributes(self, cert_pem_file):
        """
        Takes a cert pem file as an input parameter
        Returns certificate attributes as a dictionary
        """
        st_cert = open(cert_pem_file, 'rt').read()
        cert_obj = crypto.load_certificate(crypto.FILETYPE_PEM, st_cert)
        cert_attributes = {}
        extensions = []
        cert_attributes['issuer'] = cert_obj.get_issuer()
        cert_attributes['notBefore'] = cert_obj.get_notBefore()
        cert_attributes['notafter'] = cert_obj.get_notAfter()
        cert_attributes['sigAlgo'] = cert_obj.get_signature_algorithm()
        cert_attributes['subject'] = cert_obj.get_subject().get_components()
        cert_attributes['notBefore_strformat'] = datetime.strptime(cert_obj.get_notBefore(),
                                                                   "%Y%m%d%H%M%SZ")
        cert_attributes['notAfter_strformat'] = datetime.strptime(cert_obj.get_notAfter(),
                                                                  "%Y%m%d%H%M%SZ")

        ext_count = cert_obj.get_extension_count()
        for i in range(ext_count):
            ext = str(cert_obj.get_extension(i))
            extensions.append(ext)
        cert_attributes['extensions'] = extensions
        return cert_attributes
