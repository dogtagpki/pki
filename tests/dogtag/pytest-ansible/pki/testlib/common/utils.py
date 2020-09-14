#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: KRA key cli library
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   This is the library for kra-key cli tests
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Akshay Adhikari <aadhikar@redhat.com>
#           Shalini Khandelwal <skhandel@redhat.com>
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2020 Red Hat, Inc. All rights reserved.

#
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
"""
import logging
import os
import random
import re
import string
import subprocess
import sys

if os.path.isfile('/tmp/test_dir/constants.py'):
    sys.path.append('/tmp/test_dir')
    import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout)

basic_pki_cmd = 'pki -d {} -c {} -p {} -P https -n "{}" '.format(constants.NSSDB,
                                                                constants.CLIENT_DIR_PASSWORD,
                                                                constants.CA_HTTPS_PORT,
                                                                constants.CA_ADMIN_NICK)
client_cert_del = 'pki -d {} -c {} client-cert-del '.format(constants.NSSDB,
                                                            constants.CLIENT_DIR_PASSWORD)
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[1]

if TOPOLOGY != '01':
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format(constants.CA_INSTANCE_NAME,
                                                               constants.CA_SECURITY_DOMAIN_NAME)
else:
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format('pki-tomcat',
                                                               constants.CA_SECURITY_DOMAIN_NAME)


def get_random_string(len=10):
    random_string = ''.join(random.choice(string.ascii_uppercase +
                                          string.digits +
                                          string.ascii_letters)
                            for _ in range(len))
    return random_string


def system_cmd(cmd):
    """
    Invoke a shell command on localhost.
    system_cmd('ls')
    :returns: A tuple of output, err message, and return code
    """
    ret = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    out, err = ret.communicate()
    return out, err, ret.returncode


class pki_key_library(object):
    def __init__(self, **kwargs):
        self.nssdb = kwargs.get('nssdb', constants.NSSDB)
        self.db_pass = kwargs.get('db_pass', constants.CLIENT_DIR_PASSWORD)
        self.host = kwargs.get('host', constants.MASTER_HOSTNAME)

        self.protocol = kwargs.get('protocol', 'https')
        self.port = kwargs.get('port', constants.KRA_HTTPS_PORT)
        self.nick = "'{}'".format(kwargs.get('nick', constants.KRA_ADMIN_NICK))

    def generate_key(self, ansible_module, **kwargs):
        """
           This method will generate kra keys.
        """

        algo = kwargs.get('algo', 'RSA')
        key_size = kwargs.get('key_size', '2048')
        usages = kwargs.get('usages', 'wrap,unwrap')
        action = kwargs.get('action', 'approve')
        client_key_id = kwargs.get('client_key_id', 'test_{}'.format(random.randint(1111, 9999)))
        key_generate = ansible_module.pki(cli='kra-key-generate',
                                          nssdb=self.nssdb,
                                          dbpassword=self.db_pass,
                                          hostname=self.host,
                                          port=self.port,
                                          protocol=self.protocol,
                                          certnick=self.nick,
                                          extra_args='{} --key-algorithm {} --key-size {} '
                                                     '--usages {}'.format(client_key_id, algo, key_size, usages))
        result = [r for r in key_generate.values()][0]
        request_id = re.findall('Request ID:.*', result['stdout'])
        request_id = request_id[0].split(":")[1].strip()

        key_id = self.review_key_request(ansible_module, request_id, action)
        return {'key_id': key_id, 'request_id': request_id}

    def modify_key_status(self, ansible_module, key_id, status='active'):
        if status.lower() not in ['active', 'inactive']:
            log.error("Key status not valid.")
            sys.exit(1)
        key_status = ansible_module.pki(cli='kra-key-mod',
                                        nssdb=self.nssdb,
                                        dbpassword=self.db_pass,
                                        hostname=self.host,
                                        port=self.port,
                                        protocol=self.protocol,
                                        certnick=self.nick,
                                        extra_args='{} --status {}'.format(key_id, status))
        for result in key_status.values():
            if result['rc'] == 0:
                assert 'Status: {}'.format(status) in result['stdout']
                return True
            else:
                return False

    def archive_key(self, ansible_module, **kwargs):
        """
           This method will archive the keys which are generated.
        """
        passphrase = kwargs.get('passphrase', constants.CLIENT_DATABASE_PASSWORD)
        client_key_id = kwargs.get('client_key_id', 'testuser{}'.format(random.randint(1111, 9999)))

        key_archive = ansible_module.pki(cli='kra-key-archive',
                                         nssdb=self.nssdb,
                                         dbpassword=self.db_pass,
                                         hostname=self.host,
                                         port=self.port,
                                         protocol=self.protocol,
                                         certnick=self.nick,
                                         extra_args='--clientKeyID {} '
                                                    '--passphrase {} '.format(client_key_id, passphrase))

        result = [r for r in key_archive.values()][0]
        request_id = re.findall('Request ID:.*', result['stdout'])
        key_id = re.findall('Key ID:.*', result['stdout'])
        request_id = request_id[0].split(":")[1].strip()
        key_id = key_id[0].split(":")[1].strip()
        return {'request_id': request_id, 'key_id': key_id}

    def review_key_request(self, ansible_module, request_id, action='approve'):
        if request_id is None:
            raise AttributeError("Request ID not specified.")
        if action not in ['approve', 'cancel', 'reject']:
            raise KeyError("Error: Invalid action.")
        key_action = ansible_module.pki(cli='kra-key-request-review',
                                        nssdb=self.nssdb,
                                        dbpassword=self.db_pass,
                                        hostname=self.host,
                                        port=self.port,
                                        protocol=self.protocol,
                                        certnick=self.nick,
                                        extra_args='{} --action {}'.format(request_id, action))
        action_result = [r for r in key_action.values()][0]['stdout']
        raw_key_id = re.findall('Key ID:.*', action_result)
        key_id = raw_key_id[0].split(':')[1].strip()
        return key_id


class UserOperations(object):
    def __init__(self, **kwargs):
        self.nssdb = kwargs.get('nssdb', constants.NSSDB)
        self.db_pass = kwargs.get('db_pass', constants.CLIENT_DATABASE_PASSWORD)
        self.host = kwargs.get('host', constants.MASTER_HOSTNAME)
        self.nick = kwargs.get('nick', "'{}'".format(constants.CA_ADMIN_NICK))
        self.port = kwargs.get('port', constants.CA_HTTPS_PORT)
        self.protocol = kwargs.get('protocol', 'https')


    def remove_user(self, ansible_module, user, subsystem='ca'):
        """
        This method will remove the user.
        """

        port = eval("constants.{}_HTTPS_PORT".format(subsystem.upper()))
        nick = eval("constants.{}_ADMIN_NICK".format(subsystem.upper()))
        user_del = ansible_module.pki(cli='{}-user-del'.format(subsystem.lower()),
                                      nssdb=constants.NSSDB,
                                      port=port,
                                      protocol=self.protocol,
                                      certnick="'{}'".format(nick),
                                      extra_args='"{}"'.format(user))
        for host, result in user_del.items():
            log.info("Running: {}".format(result['cmd']))
            try:
                if result['rc'] == 0:
                    assert 'Deleted user'.format(user) in result['stdout']
            except Exception as e:
                log.error("Failed to add the user : {}".format(e))

    def remove_client_cert(self, ansible_module, user, subsystem='ca'):
        """
        This method will remove the user cert.
        """

        port = eval("constants.{}_HTTPS_PORT".format(subsystem.upper()))
        nick = eval("constants.{}_ADMIN_NICK".format(subsystem.upper()))
        user_cert_del = ansible_module.pki(cli='client-cert-del',
                                           nssdb=constants.NSSDB,
                                           port=port,
                                           protocol=self.protocol,
                                           certnick="'{}'".format(nick),
                                           extra_args='"{}"'.format(user))
        for host, result in user_cert_del.items():
            log.info("Running: {}".format(result['cmd']))
            try:
                if result['rc'] == 0:
                    assert 'Removed certificate "{}"'.format(user) in result['stdout']
            except Exception as e:
                log.error("Failed to remove the user cert : {}".format(e))

    def add_user(self, ansible_module, op, userid='testUser1', user_name='testUser1',
                 subsystem='ca', **kwargs):
        """
        This method will create the user.
        """
        if subsystem.lower() in ['kra', 'ocsp', 'tks', 'tps']:
            system = subsystem.upper()
            nick = eval("constants.{}_ADMIN_NICK".format(system))
            port = eval("constants.{}_HTTPS_PORT".format(system))
        else:
            nick = constants.CA_ADMIN_NICK
            port = constants.CA_HTTPS_PORT

        if op not in ['add', 'mod']:
            log.info("Operation is required. Ex: add, mod")
            sys.exit(1)

        user_params = ""
        if kwargs.get('phone', '') != '':
            user_params += " --phone '{}'".format(kwargs.get('phone', ''))
        if kwargs.get('email', '') != '':
            user_params += " --email '{}'".format(kwargs.get('email', ''))
        if kwargs.get('password', '') != '':
            user_params += " --password '{}'".format(kwargs.get('password', ''))
        if kwargs.get('state', '') != '':
            user_params += " --state '{}'".format(kwargs.get('state', ''))
        if kwargs.get('type', '') != '':
            user_params += " --type '{}'".format(kwargs.get('type', ''))
        user_add = ansible_module.pki(cli='{}-user-{}'.format(subsystem.lower(), op.lower()),
                                      nssdb=self.nssdb,
                                      dbpassword=self.db_pass,
                                      port=port,
                                      protocol=self.protocol,
                                      certnick='"{}"'.format(nick),
                                      extra_args=' {} --fullName "{}" '
                                                 '{}'.format(userid, user_name, user_params))
        for result in user_add.values():
            try:
                if result['rc'] == 0:
                    assert 'Added user' in result['stdout']
                    return True
            except Exception as e:
                log.error("Failed to add the user : {}".format(userid))
                return False

    def create_certificate_request(self, ansible_module, **kwargs):
        """
        This method will create the pkcs10 request.
        :param master: Runs on master machine if true else client machine.
        :param kwargs: This will take arguments to execution of cli.
            Required args:
                request_type = request_type. default : pkcs10
                algo = algo, default : rsa
                keysize = keysize, default: 1024
                cert_request_file = cert_request_file. default: request_<random_no>.pem
                subject = subject. default : CN=testuser,E=testuser@example.org,OU=Engineering,
                                             O=Example.Org.
                profile = profile, default: caUserCert
                transport_file = transport_file, default : /tmp/transport.pem
                crmf_request_file = crmf_request_file. default : /tmp/crmf_request_file.pem

        :param return: Returns request id of pcs10 req or crmf request id
        """

        cli_params = '"{}"'.format(kwargs.get('subject', '"CN=testuser,E=testuser@example.Org,'
                                                         'OU=Engineering,O=Example.Org"'))
        cli_params += " --algorithm {}".format(kwargs.get('algo', 'rsa'))
        if kwargs.get('algo') == 'ec':
            cli_params += " --curve {}".format(kwargs.get('curve', 'nistp256'))
        else:
            cli_params += " --length {}".format(kwargs.get('keysize', 2048))

        if kwargs.get('algo') == 'ec':
            cli_params += " --profile {}".format(kwargs.get('profile', 'caECUserCert'))
        else:
            cli_params += " --profile {}".format(kwargs.get('profile', 'caUserCert'))

        cli_params += " --type {}".format(kwargs.get('request_type', 'pkcs10'))

        transport_file = kwargs.get('transport_file', '/tmp/transport.pem')

        try:
            cert_request = ansible_module.pki(cli='client-cert-request',
                                              nssdb=self.nssdb,
                                              dbpassword=self.db_pass,
                                              port=constants.CA_HTTPS_PORT,
                                              protocol='https',
                                              certnick=self.nick,
                                              extra_args=' {}'.format(cli_params))
            for host, result in cert_request.items():
                if result['rc'] == 0:
                    request_id = re.search('Request ID: [\w]*', result['stdout'])
                    pkcs10_req_id = request_id.group().split(':')[1].strip()
                    return pkcs10_req_id
        except Exception as e:
            log.error("Failed to create client request.")
            log.info(e)

    def process_certificate_request(self, ansible_module, **kwargs):

        algo = kwargs.get('algo', 'rsa')
        profile = kwargs.get('profile', 'caUserCert')
        keysize = kwargs.get('keysize', '2048')
        curve = kwargs.get('curve', 'nistp256')
        action = kwargs.get('action', 'approve')
        revoke = kwargs.get('revoke', False)
        approver_nickname = kwargs.get('approver_nickname', self.nick)

        request_type = kwargs.get('request_type', 'pkcs10')

        cert_request_file = kwargs.get('cert_request_file',
                                       '/tmp/request_%s.pem' % random.randint(1, 99))

        transport_file = kwargs.get('transport_file', '/tmp/transport.pem')

        crmf_request_file = kwargs.get('crmf_request_file', '/tmp/crmf_request_file.pem')

        subject = kwargs.get('subject', "CN=testuser,E=testuser@example.Org,"
                                        "OU=Engineering,O=Example.Org")
        if 'request_id' in kwargs.keys():
            request_id, base64_req = kwargs['request_id'], None
        else:
            request_id = self.create_certificate_request(ansible_module,
                                                         request_type=request_type,
                                                         algo=algo,
                                                         nssdb=self.nssdb,
                                                         keysize=keysize,
                                                         curve=curve,
                                                         cert_request_file=cert_request_file,
                                                         subject=subject,
                                                         profile=profile,
                                                         transport_file=transport_file,
                                                         crmf_request_file=crmf_request_file)

        approve_request = ansible_module.pki(cli='ca-cert-request-review',
                                             nssdb=self.nssdb,
                                             dbpassword=self.db_pass,
                                             port=constants.CA_HTTPS_PORT,
                                             protocol='https',
                                             certnick='{}'.format(approver_nickname),
                                             extra_args=' {} --action {}'.format(request_id, action))

        for result in approve_request.values():
            if result['rc'] == 0:
                if action not in ['cancel', 'reject']:
                    request_id = re.findall('Certificate ID: [\w]*', result['stdout'])
                    certificate_id = request_id[0].split(':')[1].strip()
                    if revoke:
                        self.revoke_certificate(ansible_module, certificate_id, reason='Key_Compromise')
                    return certificate_id
                else:
                    return request_id
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                log.error(result['stdout'])
                log.error(result['stderr'])

    def revoke_certificate(self, ansible_module, cert_serial, reason='Key_Compromise'):
        cert_revoke = ansible_module.pki(cli='ca-cert-revoke',
                                         nssdb=self.nssdb,
                                         dbpassword=self.db_pass,
                                         port=self.port,
                                         protocol=self.protocol,
                                         certnick='{}'.format(self.nick),
                                         extra_args=' {} --force --reason {}'.format(cert_serial, reason))

        for res in cert_revoke.values():
            if res['rc'] == 0:
                log.info("Certificate {} Revoked".format(cert_serial))
                return cert_serial

    def get_cert(self, ansible_module, user, serial, remove_cert=True):
        import_cert = basic_pki_cmd + ' client-cert-import {} --serial {}'.format(user, serial)
        import_out = ansible_module.command(import_cert)
        for result in import_out.values():
            if result['rc'] == 0:
                assert 'Imported certificate "{}"'.format(user) in result['stdout']
                pem_file = '/tmp/{}_{}.pem'.format(user, serial)
                export_cert = basic_pki_cmd + 'client-cert-show "{}" --cert {}'.format(user, pem_file)
                log.info("Imported certificate for user '{}'".format(user))
                ansible_module.command(export_cert)
                file_stat = ansible_module.stat(path=pem_file)
                for result1 in file_stat.values():
                    assert result1['stat']['exists']
                    log.info("Certificate stored in to file: {}.".format(pem_file))
                    if remove_cert:
                        ansible_module.command(client_cert_del + user)
                    return pem_file
                log.info('Successfully ran : {}'.format(result['cmd']))
            else:
                log.error("Failed to import certificate.")
                sys.exit(1)

    def add_cert_to_user(self, ansible_module, user, serial, subsystem='ca', remove_cert=True):
        if subsystem.lower() in ['kra', 'ocsp', 'tks', 'tps']:
            system = subsystem.upper()
            nick = eval("constants.{}_ADMIN_NICK".format(system))
            port = eval("constants.{}_HTTPS_PORT".format(system))
        else:
            nick = constants.CA_ADMIN_NICK
            port = constants.CA_HTTPS_PORT
        cert_file = self.get_cert(ansible_module, user, serial, remove_cert=remove_cert)
        cmd_out = ansible_module.pki(cli='{}-user-cert-add'.format(subsystem.lower()),
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=port,
                                     protocol=self.protocol,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(nick),
                                     extra_args='{} --input {}'.format(user, cert_file))

        for result in cmd_out.values():
            log.info("Running: {}".format(result['cmd']))
            if result['rc'] == 0:
                assert 'Added certificate' in result['stdout']
                assert 'Serial Number: {}'.format(serial) in result['stdout']
                log.info("Added certificate to user {}".format(user))
                return True
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                return False
        ansible_module.command('rm -rf {}'.format(cert_file))


class ProfileOperations(object):
    def __init__(self, **kwargs):
        self.nssdb = kwargs.get('nssdb', constants.NSSDB)
        self.db_pass = kwargs.get('db_pass', "'{}'".format(constants.CLIENT_DATABASE_PASSWORD))
        self.host = kwargs.get('host', 'pki1.example.com')
        self.port = kwargs.get('port', '{}'.format(constants.CA_HTTPS_PORT))
        self.protocol = kwargs.get('protocol', 'https')
        self.nick = kwargs.get('nick', "'{}'".format(constants.CA_ADMIN_NICK))

    def get_profile_to_xml(self, ansible_module, profile_name='caUserCert',
                           profile_path='/tmp/caUserCert.xml'):

        get_profile = ansible_module.pki(cli='ca-profile-show',
                                         nssdb=self.nssdb,
                                         dbpassword=self.db_pass,
                                         port=constants.CA_HTTPS_PORT,
                                         protocol='https',
                                         certnick=self.nick,
                                         extra_args='{} --output {}'.format(profile_name,
                                                                            profile_path))

        for result in get_profile.values():
            if result['rc'] == 0:
                assert 'Saved profile {} to {}'.format(profile_name, profile_path) in \
                       result['stdout']
                return True
            else:
                return False

    def add_profile(self, ansible_module, profile_name, profile_path):
        """
        :param ansible_module:
        :param profile:
        :return:
        """
        added_prof = False
        add_profile = ansible_module.pki(cli='ca-profile-add',
                                         nssdb=self.nssdb,
                                         dbpassword=self.db_pass,
                                         port=constants.CA_HTTPS_PORT,
                                         protocol='https',
                                         certnick=self.nick,
                                         extra_args=profile_path)

        for result in add_profile.values():
            if result['rc'] == 0:
                if 'Added profile {}'.format(profile_name) in result['stdout']:
                    return True
            else:
                return False

    def enable_profile(self, ansible_module, profile_name):

        enable_profile = ansible_module.pki(cli='ca-profile-enable',
                                            nssdb=self.nssdb,
                                            dbpassword=self.db_pass,
                                            port=constants.CA_HTTPS_PORT,
                                            protocol='https',
                                            certnick=self.nick,
                                            extra_args=profile_name)
        for res in enable_profile.values():
            if res['rc'] == 0:
                if 'Enabled profile "{}"'.format(profile_name) in res['stdout']:
                    return True
            else:
                return False

    def disable_profile(self, ansible_module, profile_name):

        disable_profile = ansible_module.pki(cli='ca-profile-disable',
                                             nssdb=self.nssdb,
                                             dbpassword=self.db_pass,
                                             port=constants.CA_HTTPS_PORT,
                                             protocol='https',
                                             certnick=self.nick,
                                             extra_args=profile_name)
        for res in disable_profile.values():
            try:
                if res['rc'] == 0:
                    assert 'Disabled profile "{}"'.format(profile_name) in res['stdout']
            except Exception as e:
                log.error("Failed to disable profile {}.".format(profile_name))
                log.error(e)
                sys.exit(1)

    def delete_profile(self, ansible_module, profile_name):
        """
        This method will delete the profile
        """
        delete_profile = ansible_module.pki(cli='ca-profile-del',
                                            nssdb=self.nssdb,
                                            dbpassword=self.db_pass,
                                            port=constants.CA_HTTPS_PORT,
                                            protocol='https',
                                            certnick=self.nick,
                                            extra_args=profile_name)
        for res in delete_profile.values():
            try:
                if res['rc'] == 0:
                    if 'Deleted profile "{}"'.format(profile_name) in res['stdout']:
                        return True
                else:
                    return False
            except Exception as e:
                log.error("Failed to delete the profile")
                log.error(e)
                sys.exit(1)
