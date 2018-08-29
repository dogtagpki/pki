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

import os
import re
import sys
from datetime import datetime
from subprocess import CalledProcessError

import OpenSSL.crypto as crypto
import pytest

from pki.testlib.common.exceptions import PkiLibException
from pki.testlib.common.profile import Setup

if os.path.isfile('/tmp/test_dir/constants.py'):
    sys.path.append('/tmp/test_dir')
    import constants


class CertSetup(object):
    """
    This class contains methods to create a certdb, adding certs to db,
    create role users
    """
    def __init__(self, **kwargs):
        self.nssdb = kwargs.get('nssdb', '/tmp/nssdb')
        self.db_pass = kwargs.get('db_pass', 'SECret.123')
        self.host = kwargs.get('host', 'pki1.example.com')
        self.protocol = kwargs.get('protocol', 'http')
        self.port = kwargs.get('port', constants.CA_HTTP_PORT)
        self.nick = kwargs.get('nick', constants.CA_ADMIN_NICK)
        self.subsystem = kwargs.get('subsystem', "CA")

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
        create_cert_db = ansible_module.command(client_init)
        for result in create_cert_db.values():
            if 'Security database already exists' in result['stdout']:
                raise Exception('Security Database already Exists', '255')
            else:
                assert "Client initialized" in result['stdout']
                print("Created certdb {}".format(self.nssdb))

    def import_admin_p12(self, ansible_module, subsystem):
        """
        Import subsystem admin p12 to certdb
        """
        pkcs12path = self.pkcs12_path(subsystem)
        import_admin_p12 = ansible_module.pki(
            cli='client-cert-import',
            nssdb=self.nssdb,
            dbpassword=self.db_pass,
            port=self.port,
            extra_args='--pkcs12 {} '
                       '--pkcs12-password {} '.format(pkcs12path, constants.CLIENT_PKCS12_PASSWORD)
        )
        for result in import_admin_p12.values():
            assert "Imported certificate" in result['stdout']
            print("Imported {} admin cert, {}".format(subsystem, pkcs12path))

    def import_ca_cert(self, ansible_module):
        """
        Import CA cert to certdb
        """
        import_ca_cert = ansible_module.pki(
            cli='client-cert-import',
            nssdb=self.nssdb,
            dbpassword=self.db_pass,
            port=self.port,
            certnick="RootCA",
            extra_args="--ca-server"
        )
        for result in import_ca_cert.values():
            assert "Imported certificate \"RootCA\"" in result['stdout']
            print("Imported CA cert")

    def setup_role_users(self, ansible_module, subsystem, admin_nick, ca_http_port=None,
                         ca_agent_nick=None, duration='day'):
        """
        Create various role users needed for cli tests
        """
        user_identifier = ['E', 'R', 'V', 'UnTrusted']
        roles = ['Agent', 'Admin', 'Audit', 'UnPrivileged']
        common_groups = ['Certificate Manager Agents', 'Administrators', 'Auditors', 'UnPrivileged']
        tps_roles = ['Agent', 'Admin', 'Operator', 'Unprivileged']
        tps_groups = ['TPS Agents', 'Administrators', 'TPS Operators', 'UnPrivileged']

        # create a group UnPrivileged
        create_unprivileged_group = ansible_module.pki(
            cli="{} group-add".format(subsystem),
            nssdb=self.nssdb,
            dbpassword=self.db_pass,
            port=self.port,
            certnick=self.nick,
            extra_args="UnPrivileged"
        )

        if subsystem is 'ca':
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
                self.enable_profile(ansible_module, profileid, user_nick=admin_nick)
            except PkiLibException as err:
                pytest.xfail("Unable to enable profile, failed with error: %s" % (err.msg))
        count = 0
        if subsystem is 'tps':
            roles = tps_roles
            common_groups = tps_groups
        for role in roles:
            for u_id in user_identifier:
                user_name = "%s_%s%s" % (subsystem.upper(), role, u_id)
                if (subsystem == 'kra') and (role == 'Agent'):
                    group_name = 'Data Recovery Manager Agents'
                elif (subsystem == 'ocsp') and (role == 'Agent'):
                    group_name = 'Online Certificate Status Manager Agents'
                elif (subsystem == 'tps') and (role == 'Agent'):
                    group_name = 'TPS Agents'
                elif (subsystem == 'tps') and (role == 'Auditors'):
                    group_name = 'TPS Operators'
                else:
                    group_name = common_groups[count]
                if self.create_role_user(ansible_module, admin_nick, subsystem, user_name, group_name):
                    subject_dn = ("UID=%s,E=%s@example.org,CN=%s,"
                                  "OU=IDMQE,C=US") % (user_name, user_name, user_name)
                    if u_id is 'E':
                        cert_serial = self.create_user_cert(ansible_module, subject_dn, 'caAgentFoobar',
                                                            ca_http_port, ca_agent_nick)
                    else:
                        cert_serial = self.create_user_cert(ansible_module, subject_dn, 'caUserCert',
                                                            ca_http_port, ca_agent_nick)
                    if u_id is 'R':
                        (msg, return_code) = self.revoke_cert(ansible_module, ca_agent_nick, cert_serial,
                                                              'Key_Compromise', ca_http_port)

                    [returncode, output_text] = self.add_user_cert(ansible_module, admin_nick, subsystem,
                                                                   user_name, cert_serial,
                                                                   ca_http_port)
                    if returncode is 0:
                        [returncode, output_text] = self.import_cert_to_certdb(ansible_module, cert_serial,
                                                                               user_name,
                                                                               ca_http_port)
                        if returncode is not 0:
                            return False
                    else:
                        return False
            count += 1
        return True

    def revoke_cert(self, ansible_module, user_nick, cert_serial_number, reason, ca_http_port=None):
        ''' Revoke Certificate with with given reason
        :param str user_nick: Nickname of the user using which role user should be added
            if None, it uses Admin cert
        :param str cert_serial_number: serial Number of the cert
        :param str reason: Revocation reason
        :param str ca_http_port: CA Subsystem HTTP Port

        :Raise PKiLibException

        :Returns stdout_text, returncode
        '''
        if user_nick is None:
            user_nick = constants.CA_ADMIN_NICK
        if ca_http_port is None:
            ca_http_port = constants.CA_HTTP_PORT
        try:
            revoke_cert = ansible_module.pki(
                cli="cert-revoke",
                nssdb=self.nssdb,
                dbpassword=self.db_pass,
                hostname=self.host,
                port=constants.CA_HTTP_PORT,
                certnick="'{}'".format(user_nick),
                extra_args="{} --force --reason {}".format(cert_serial_number, reason)
            )
        except CalledProcessError as err:
            raise PkiLibException('Unable to revoke cert', err.returncode)
        else:
            output = None
            for output in revoke_cert.values():
                pass
            print("Successfully revoked cert %s with reason %s" % (cert_serial_number, reason))
            return (output['stdout'], output['rc'])

    def create_role_user(self, ansible_module, user_nick, subsystem, userid, groupid):
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
        if user_nick is None:
            user_nick = self.nick,
        try:
            user_add = ansible_module.pki(
                cli="{} user-add {} --fullName {}".format(subsystem, userid, userid),
                nssdb=self.nssdb,
                dbpassword=self.db_pass,
                port=self.port,
                certnick="'{}'".format(user_nick)
            )
        except CalledProcessError as err:
            raise PkiLibException('Unable to create user cert', err.returncode)
        else:
            print("Successfully created user %s" % (userid))
        try:
            group_member_add = ansible_module.pki(
                cli="{} group-member-add".format(subsystem),
                nssdb=self.nssdb,
                dbpassword=self.db_pass,
                port=self.port,
                certnick=self.nick,
                extra_args="'{}' {}".format(groupid, userid)
            )
        except CalledProcessError as err:
            raise PkiLibException('Unable to add %s to role %s' % (userid, groupid), err.returncode)
        else:
            print("Successfully added user %s to role %s" % (userid, groupid))
            return True

    def create_user_cert(self, ansible_module, cert_subject, profile=None, ca_http_port=None, ca_agent_nick=None,
                         ca_hostname=None):
        ''' Create certificate to the subsystem user and add certificate to certdb
        :param str cert_subject: Subject to be used to create certificate reqeust
        :returns None
        :raises PkiLibException if create of certificate request or approving fails
        '''
        if ca_agent_nick is not None and '\'' not in ca_agent_nick:
            ca_agent_nick = "'{}'".format(ca_agent_nick)
        if profile is None:
            profile = 'caUserCert'
        if ca_http_port is None:
            ca_http_port = constants.CA_HTTP_PORT
        if ca_agent_nick is None:
            ca_agent_nick = self.nick
        if ca_hostname is None:
            ca_hostname = self.host
        try:
            create_user_cert = ansible_module.pki(
                cli="client-cert-request",
                nssdb=self.nssdb,
                dbpassword=self.db_pass,
                hostname=self.host,
                port=constants.CA_HTTP_PORT,
                certnick=self.nick,
                extra_args="{} --profile {}".format(cert_subject, profile)
            )
        except CalledProcessError as err:
            raise PkiLibException('Unable to create cert with subject %s' % (cert_subject),
                                  err.returncode)
        else:
            try:
                output = None
                for result in create_user_cert.values():
                    output = result['stdout']
                request_id = re.search('Request ID: [\w]*', output)
                r_id = request_id.group().split(':')[1].strip()
            except:
                raise PkiLibException("Failed to grep Request ID for user cert %s" % cert_subject)
            try:
                cert_request_review = ansible_module.pki(
                    cli="cert-request-review",
                    nssdb=self.nssdb,
                    dbpassword=self.db_pass,
                    hostname=self.host,
                    port=constants.CA_HTTP_PORT,
                    certnick="'{}'".format(constants.CA_ADMIN_NICK),
                    extra_args="{} --action approve".format(r_id)
                )
            except CalledProcessError as err:
                raise PkiLibException('Unable to approve certificate request %s' % (r_id),
                                      err.returncode)
            else:
                try:
                    output = None
                    for result in cert_request_review.values():
                        output = result['stdout']
                    cert_id = re.search('Certificate ID: [\w]*', output)
                    c_id = cert_id.group().split(':')[1].strip()
                    return c_id
                except:
                    raise PkiLibException("Failed to grep Certificate ID for user cert %s" % r_id)

    def add_user_cert(self, ansible_module, user_nick, subsystem, userid, cert_serial_number, ca_http_port=None):
        ''' Add certificate to the subsystem user
        :param str subsystem: Subsystem to which user should be added
        :param str user_nick: Nickname of the user using which role user should be added
            if None, it uses Admin cert
        :param str userid: User id to be added
        :param str cert_serial_number: serial Number of the cert

        :Returns list Returncode, output_text

        :Raises PkiLibException
        '''
        if user_nick is None:
            user_nick = constants.CA_ADMIN_NICK,
        if subsystem is not 'ca':
            if ca_http_port is None:
                ca_http_port = constants.CA_HTTP_PORT
            [msg, output_file] = self.cert_show(ansible_module, cert_serial_number, ca_http_port)

            try:
                add_user_cert = ansible_module.pki(
                    cli="{} user-cert-add {} --input {}".format(subsystem, userid, output_file),
                    nssdb=self.nssdb,
                    dbpassword=self.db_pass,
                    hostname=self.host,
                    port=self.port,
                    certnick="'{}'".format(user_nick),
                )
            except CalledProcessError as err:
                raise PkiLibException('Unable to add certificate to subsystem user %s'
                                      % (userid), err.returncode)
            else:
                result = None
                for result in add_user_cert.values():
                    pass
                return [result['rc'], result['stdout']]
        else:
            try:
                user_cert_add_output = ansible_module.pki(
                    cli="{} user-cert-add {} --serial {}".format(subsystem, userid, cert_serial_number),
                    nssdb=self.nssdb,
                    dbpassword=self.db_pass,
                    hostname=self.host,
                    port=constants.CA_HTTP_PORT,
                    certnick="'{}'".format(user_nick),
                )
            except CalledProcessError as err:
                raise PkiLibException('Unable to add certificate to subsystem user %s'
                                      % (userid), err.returncode)
            else:
                result = None
                for result in user_cert_add_output.values():
                    pass
                return [result['rc'], result['stdout']]

    def import_cert_to_certdb(self, ansible_module, cert_serial_number, nickname, ca_http_port=None):
        ''' Import certificate to certdb
        :param str cert_serial_number: serial Number of the cert
        :param str nickname: nickname to be used to import the cert to certdb
        :Returns None
        :Raises PkiLibException if importing the cert fails
        '''
        if ca_http_port is None:
            ca_http_port = constants.CA_HTTP_PORT
        try:
            import_to_certdb = ansible_module.pki(
                cli="client-cert-import",
                nssdb=self.nssdb,
                dbpassword=self.db_pass,
                hostname=self.host,
                port=constants.CA_HTTP_PORT,
                certnick=nickname,
                extra_args="--serial {}".format(cert_serial_number)
            )
        except CalledProcessError as err:
            raise PkiLibException('Unable to import cert %s to certdb %s' % (
                cert_serial_number, constants.NSSDB), err.returncode)
        else:
            print("Successfully added cert %s to certdb %s with nick %s" % (
                cert_serial_number, constants.NSSDB, nickname))
            result = None
            for result in import_to_certdb.values():
                pass
            return [result['rc'], result['stdout']]

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
        destination_profile_path = "%s/new-%s.xml" % ('/tmp', profile_id)
        try:
            file_contents = None
            with open(profile_xml) as infile:
                file_contents = infile.read()
            ansible_module.copy(content=file_contents, dest=destination_profile_path)
        except IOError as err:
            raise PkiLibException("Unable to copy file")
        try:
            create_profile = ansible_module.pki(
                cli="ca-profile-add",
                nssdb=self.nssdb,
                dbpassword=self.db_pass,
                port=self.port,
                certnick=self.nick,
                extra_args=destination_profile_path
            )
        except CalledProcessError as err:
            raise PkiLibException('Unable to add profile :%s' % (profile_xml), err.returncode)
        else:
            print("Successfully added profile %s" % (profile_xml))
            return True

    def enable_profile(self, ansible_module, profile_id, user_nick=None):
        ''' Enable a profile as user_nick
        :param str profile_id: Profile Name
        :param str user_nick: Certificate Nick to be used to submit the request, if none, CA Admin
            cert will be used to submit the request
        :Returns None
        :Raises PkiLibException if profile could not be enabled
        '''
        if user_nick is None:
            user_nick = self.nick
        try:
            enable_profile = ansible_module.pki(
                cli="ca-profile-enable",
                nssdb=self.nssdb,
                dbpassword=self.db_pass,
                port=self.port,
                certnick=self.nick,
                extra_args=profile_id
            )
        except CalledProcessError as err:
            raise PkiLibException('Unable to enable profile :%s' % (profile_id), err.returncode)
        else:
            print("Successfully enabled profile %s " % (profile_id))
            return True

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
                port=constants.CA_HTTP_PORT,
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
