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
import os
import re
import random

if os.path.isfile('/tmp/test_dir/constants.py'):
    import sys

    sys.path.append('/tmp/test_dir')
    import constants


class pki_key_library(object):
    def __init__(self, **kwargs):
        self.nssdb = kwargs['nssdb'] if 'nssdb' in kwargs.keys() else '/tmp/nssdb'
        self.db_pass = kwargs['db_pass'] if 'db_pass' in kwargs.keys() else 'Secret123'
        self.host = kwargs['host'] if 'host' in kwargs.keys() else 'pki1.example.com'
        self.protocol = kwargs['protocol'] if 'protocol' in kwargs.keys() else 'http'
        self.port = kwargs['port'] if 'port' in kwargs.keys() else constants.CA_ADMIN_PORT
        self.nick = kwargs['nick'] if 'nick' in kwargs.keys() else constants.CA_ADMIN_NICK
    def generate_key(self, ansible_module, **kwargs):
        """
           This method will generate kra keys.
        """

        algo = kwargs['algo'] if 'algo' in kwargs.keys() else 'RSA'
        key_size = kwargs['key_size'] if 'key_size' in kwargs.keys() else '2048'
        usages = kwargs['usages'] if 'usages' in kwargs.keys() else 'wrap,unwrap'
        action = kwargs['action'] if 'action' in kwargs.keys() else 'approve'
        client_key_id = kwargs['client_key_id'] if 'client_key_id' in kwargs.keys() else 'test_%s' % random.randint(
            1111, 9999)

        key_generate = ansible_module.pki(
            cli='kra-key-generate',
            hostname='pki1.example.com',
            port=self.port,
            protocol=self.protocol,
            certnick=self.nick,
            extra_args='{} --key-algorithm {} '
                       '--key-size {} '
                       '--usages {}'.format(client_key_id, algo, key_size, usages))
        result = [r for h, r in key_generate.items()][0]
        try:
            request_id = re.search('Request ID: [\w]*', result['stdout']).group().encode('utf-8')
            request_id = request_id.split(":")[1].strip()

        except Exception as e:
            print(e)

        try:
            if result['rc'] == 0:
                key_action = ansible_module.pki(
                    cli='key-request-review',
                    hostname='pki1.example.com',
                    port=self.port,
                    protocol=self.protocol,
                    certnick=self.nick,
                    extra_args='{} --action {}'.format(request_id, action))

                action_result = [r for h, r in key_action.items()][0]['stdout']
                key_id = re.search('Key ID: [\w]*', action_result).group().split(':')[1].strip()
                return key_id
        except Exception as e:
            print(e)

    def archive_passphrase(self, ansible_module, **kwargs):
        """
           This method will archive the keys which are generated.
        """
        passphrase = kwargs['passphrase'] if 'passphrase' in kwargs.keys() else 'secret'
        action = kwargs['action'] if 'action' in kwargs.keys() else 'approve'
        client_key_id = kwargs['client_key_id'] if 'client_key_id' in kwargs.keys() else 'testuser%s' % random.randint(
            1111, 9999)

        key_archive = ansible_module.pki(
            cli='kra-key-archive',
            hostname='pki1.example.com',
            port=self.port,
            protocol=self.protocol,
            certnick=self.nick,
            extra_args='--clientKeyID {} --passphrase {} '.format(client_key_id, passphrase))

        result = [r for h, r in key_archive.items()][0]

        request_id = re.search('Request ID: [\w]*', result['stdout']).group().encode('utf-8')
        request_id = request_id.split(":")[1].strip()

        try:
            if result['rc'] == 0:
                key_action = ansible_module.pki(
                    cli='key-request-review',
                    hostname='pki1.example.com',
                    port=self.port,
                    protocol=self.protocol,
                    certnick=self.nick,
                    extra_args='{} --action {}'.format(request_id, action))
                action_result = [r for h, r in key_action.items()][0]['stdout']
                key_id = re.search('Key ID: [\w]*', action_result).group().split(':')[1].strip()
                return key_id
        except Exception as e:
            print(e)


class pki_generate_cert_library(object):
    def __init__(self, **kwargs):
        self.nssdb = kwargs['nssdb'] if 'nssdb' in kwargs.keys() else '/tmp/nssdb'
        self.db_pass = kwargs['db_pass'] if 'db_pass' in kwargs.keys() else 'Secret123'
        self.host = kwargs['host'] if 'host' in kwargs.keys() else 'pki1.example.com'
        self.protocol = kwargs['protocol'] if 'protocol' in kwargs.keys() else 'http'
        self.port = kwargs['port'] if 'port' in kwargs.keys() else constants.CA_ADMIN_PORT
        self.nick = kwargs['nick'] if 'nick' in kwargs.keys() else constants.CA_ADMIN_NICK

    def add_user(self, ansible_module, userid='testuser1234', user_name='testuser1234', subsystem='ca',
                 certnick=constants.CA_ADMIN_NICK, **kwargs):
        """
        This method will create the user.
        """
        check_user = ansible_module.pki(
            cli='{}-user-show'.format(subsystem.lower()),
            hostname='pki1.example.com',
            certnick=certnick,
            extra_args=' {}'.format(userid))
        for host1, result1 in check_user.items():
            if result1['rc'] == 255:
                user_params = ""
                user_params += " --phone " + kwargs['phone'] if 'phone' in kwargs.keys() else ""
                user_params += " --email " + kwargs['email'] if 'email' in kwargs.keys() else ""
                user_params += " --password " + kwargs['password'] if 'password' in kwargs.keys() else ""
                user_params += " --state " + kwargs['state'] if 'state' in kwargs.keys() else ""
                user_params += " --type " + kwargs['type'] if 'type' in kwargs.keys() else ""

                user_add = ansible_module.pki(
                    cli='{}-user-add'.format(subsystem.lower()),
                    hostname='pki1.example.com',
                    certnick=certnick,
                    extra_args=' {} --fullName {} {}'.format(userid, user_name, user_params))
                for host, result in user_add.items():
                    try:
                        assert result['rc'] == 0
                        if result['rc'] == 0:
                            assert 'Added user "{}"'.format(userid) in result['stdout']
                            return 0
                    except Exception as e:
                        print("Failed to add the user : {}".format(e))
            else:
                return 255

    def create_certificate_request(self, ansible_module, **kwargs):
        """
           This method will create a certificate request.
        """
        subject = kwargs['subject'] if 'subject' in kwargs.keys() else "UID=testuser1234,CN=testuser1234," \
                                                                       "E=testuser1234@example.Org," \
                                                                       "OU=Engineering," \
                                                                       "O=Example.Org"
        profile = kwargs['profile'] if 'profile' in kwargs.keys() else 'caUserCert'

        try:
            cert_request = ansible_module.pki(
                cli='client-cert-request {}'.format(subject),
                hostname='pki1.example.com',
                port=constants.CA_HTTP_PORT,
                extra_args='--profile {}'.format(profile))
            for host, result in cert_request.items():
                if result['rc'] == 0:
                    request_id = re.search('Request ID: [\w]*', result['stdout'])
                    global pkcs10_req_id
                    pkcs10_req_id= request_id.group().split(':')[1].strip()
        except Exception as e:
            print("Failed to create client request.")
            print(e)


    def process_certificate_request(self, ansible_module,
                                    certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                    **kwargs):
        """
           This method will process a certificate request.
        """

        action = kwargs['action'] if 'action' in kwargs.keys() else 'approve'
        try:
            cert_req_review = ansible_module.pki(
                cli='cert-request-review {}'.format(pkcs10_req_id.lower()),
                hostname='pki1.example.com',
                port=constants.CA_HTTP_PORT,
                certnick=certnick,
                extra_args='--action {}'.format(action))
            for result in cert_req_review.values():
                if result['rc'] == 0:
                    cert_id = re.search('Certificate ID: [\w]*', result['stdout'])
                    global serial
                    serial = cert_id.group().split(':')[1].strip()
                    print('client request proceeded')
        except Exception as e:
            print("Failed to process client request.")
            print(e)



    def export_certificate(self, ansible_module,
                                    certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                    **kwargs):
        """
           This method will export the certificate to a default location.
        """

        output = kwargs['output'] if 'output' in kwargs.keys() else '/opt/rhqa_pki/'+serial+'.pem'
        try:
            export_cert = ansible_module.pki(
                cli='cert-show {}'.format(serial.lower()),
                hostname='pki1.example.com',
                port=constants.CA_HTTP_PORT,
                certnick=certnick,
                extra_args='--pretty --output {} '.format(output))
            for result in export_cert.values():
                if result['rc'] == 0:
                    print('client certificate exported')
        except Exception as e:
            print('Failed to process client export request')
            print(e)

    def add_cert_to_user(self, ansible_module,userid='testuser1234',subsystem='ca',
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                    **kwargs):
        """
           This method will add certificate to user.
        """
        input = kwargs['input'] if 'input' in kwargs.keys() else '/opt/rhqa_pki/'+serial+'.pem'
        try:
            add_cert = ansible_module.pki(
                cli='{} user-cert-add {}'.format(subsystem,userid),
                hostname='pki1.example.com',
                port=port,
                certnick=certnick,
                extra_args=' --input {} '.format(input))
            for result in add_cert.values():
                if result['rc'] == 0:
                    print('client certificate added to user')
        except Exception as e:
            print('Failed to add client certificate to user')
            print(e)

    def add_cert_to_database(self, ansible_module,userid='testuser1234',port=constants.CA_HTTP_PORT):

        """
           This method will add the certificate to the nssdb(database).
        """

        try:
            add_to_db = ansible_module.pki(
                cli=' client-cert-import {}'.format(userid),
                hostname='pki1.example.com',
                port=port,
                extra_args=' --serial {} '.format(serial))
            for result in add_to_db.values():
                if result['rc'] == 0:
                    print('client certificate added to DB')
        except Exception as e:
            print('Failed to add client certificate to DB')
            print(e)