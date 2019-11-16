# Authors:
#     Matthew Harmsen <mharmsen@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2012 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function
import logging
import os

import pki.nssdb
import pki.pkcs12
import pki.server
import pki.util

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkiscriptlet

logger = logging.getLogger('nssdb')


# PKI Deployment Security Databases Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping NSS database creation')
            return

        logger.info('Creating NSS database')

        instance = pki.server.instance.PKIInstance(deployer.mdict['pki_instance_name'])
        instance.load()

        subsystem = instance.get_subsystem(deployer.mdict['pki_subsystem'].lower())

        if config.str2bool(deployer.mdict['pki_hsm_enable']):
            hsm_token = deployer.mdict['pki_token_name']
            subsystem.config['preop.module.token'] = hsm_token

        # Since 'certutil' does NOT strip the 'token=' portion of
        # the 'token=password' entries, create a temporary server 'pfile'
        # which ONLY contains the 'password' for the purposes of
        # allowing 'certutil' to generate the security databases

        logger.info('Creating password file: %s', deployer.mdict['pki_shared_pfile'])
        deployer.password.create_password_conf(
            deployer.mdict['pki_shared_pfile'],
            deployer.mdict['pki_server_database_password'], pin_sans_token=True)
        deployer.file.modify(deployer.mdict['pki_shared_password_conf'])

        if not os.path.isdir(deployer.mdict['pki_server_database_path']):
            instance.makedirs(deployer.mdict['pki_server_database_path'], force=True)

        deployer.certutil.create_security_databases(
            deployer.mdict['pki_server_database_path'],
            password_file=deployer.mdict['pki_shared_pfile'])

        if not os.path.islink(deployer.mdict['pki_instance_database_link']):
            instance.symlink(
                deployer.mdict['pki_server_database_path'],
                deployer.mdict['pki_instance_database_link'],
                force=True)

        instance.symlink(
            deployer.mdict['pki_instance_database_link'],
            deployer.mdict['pki_subsystem_database_link'],
            force=True)

        if config.str2bool(deployer.mdict['pki_hsm_enable']):
            deployer.modutil.register_security_module(
                deployer.mdict['pki_server_database_path'],
                deployer.mdict['pki_hsm_modulename'],
                deployer.mdict['pki_hsm_libfile'])
        pki.util.chown(
            deployer.mdict['pki_server_database_path'],
            deployer.mdict['pki_uid'],
            deployer.mdict['pki_uid'])
        pki.util.chmod(
            deployer.mdict['pki_server_database_path'],
            config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)
        os.chmod(
            deployer.mdict['pki_server_database_path'],
            config.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS)

        # import system certificates before starting the server

        pki_server_pkcs12_path = deployer.mdict['pki_server_pkcs12_path']
        if pki_server_pkcs12_path:

            pki_server_pkcs12_password = deployer.mdict[
                'pki_server_pkcs12_password']
            if not pki_server_pkcs12_password:
                raise Exception('Missing pki_server_pkcs12_password property.')

            nssdb = pki.nssdb.NSSDatabase(
                directory=deployer.mdict['pki_server_database_path'],
                password_file=deployer.mdict['pki_shared_pfile'])

            try:
                nssdb.import_pkcs12(
                    pkcs12_file=pki_server_pkcs12_path,
                    pkcs12_password=pki_server_pkcs12_password)
            finally:
                nssdb.close()

            # update external CA file (if needed)
            external_certs_path = deployer.mdict['pki_server_external_certs_path']
            if external_certs_path is not None:
                self.update_external_certs_conf(external_certs_path, deployer)

        # import CA certificates from PKCS #12 file for cloning
        pki_clone_pkcs12_path = deployer.mdict['pki_clone_pkcs12_path']

        if pki_clone_pkcs12_path:

            pki_clone_pkcs12_password = deployer.mdict[
                'pki_clone_pkcs12_password']
            if not pki_clone_pkcs12_password:
                raise Exception('Missing pki_clone_pkcs12_password property.')

            nssdb = pki.nssdb.NSSDatabase(
                directory=deployer.mdict['pki_server_database_path'],
                password_file=deployer.mdict['pki_shared_pfile'])

            try:
                print('Importing certificates from %s:' % pki_clone_pkcs12_path)

                # The PKCS12 class requires an NSS database to run. For simplicity
                # it uses the NSS database that has just been created.
                pkcs12 = pki.pkcs12.PKCS12(
                    path=pki_clone_pkcs12_path,
                    password=pki_clone_pkcs12_password,
                    nssdb=nssdb)

                try:
                    pkcs12.show_certs()
                finally:
                    pkcs12.close()

                # Import certificates
                nssdb.import_pkcs12(
                    pkcs12_file=pki_clone_pkcs12_path,
                    pkcs12_password=pki_clone_pkcs12_password)

                # Set certificate trust flags
                if subsystem.type == 'CA':
                    nssdb.modify_cert(
                        nickname=deployer.mdict['pki_ca_signing_nickname'],
                        trust_attributes='CTu,Cu,Cu')

                nssdb.modify_cert(
                    nickname=deployer.mdict['pki_audit_signing_nickname'],
                    trust_attributes='u,u,Pu')

                print('Imported certificates into %s:' %
                      deployer.mdict['pki_server_database_path'])

                nssdb.show_certs()

            finally:
                nssdb.close()

        if len(deployer.instance.tomcat_instance_subsystems()) < 2:

            # Check to see if a secure connection is being used for the DS
            if config.str2bool(deployer.mdict['pki_ds_secure_connection']):
                # Check to see if a directory server CA certificate
                # using the same nickname already exists
                #
                # NOTE:  ALWAYS use the software DB regardless of whether
                #        the instance will utilize 'softokn' or an HSM
                #
                rv = deployer.certutil.verify_certificate_exists(
                    path=deployer.mdict['pki_server_database_path'],
                    token=deployer.mdict['pki_self_signed_token'],
                    nickname=deployer.mdict[
                        'pki_ds_secure_connection_ca_nickname'
                    ],
                    password_file=deployer.mdict['pki_shared_pfile'])
                if not rv:
                    # Import the directory server CA certificate
                    rv = deployer.certutil.import_cert(
                        deployer.mdict['pki_ds_secure_connection_ca_nickname'],
                        deployer.mdict[
                            'pki_ds_secure_connection_ca_trustargs'],
                        deployer.mdict['pki_ds_secure_connection_ca_pem_file'],
                        password_file=deployer.mdict['pki_shared_pfile'],
                        path=deployer.mdict['pki_server_database_path'],
                        token=deployer.mdict['pki_self_signed_token'])

        # Always delete the temporary 'pfile'
        deployer.file.delete(deployer.mdict['pki_shared_pfile'])

        # Store system cert parameters in installation step to guarantee the
        # parameters exist during configuration step and to allow customization.

        certs = subsystem.find_system_certs()
        for cert in certs:

            # get CS.cfg tag and pkispawn tag
            config_tag = cert['id']
            deploy_tag = config_tag

            if config_tag == 'signing':  # for CA and OCSP
                deploy_tag = subsystem.name + '_signing'

            # store nickname
            nickname = deployer.mdict['pki_%s_nickname' % deploy_tag]
            subsystem.config['%s.%s.nickname' % (subsystem.name, config_tag)] = nickname
            subsystem.config['preop.cert.%s.nickname' % config_tag] = nickname

            # store tokenname
            tokenname = deployer.mdict['pki_%s_token' % deploy_tag]
            subsystem.config['%s.%s.tokenname' % (subsystem.name, config_tag)] = tokenname

            # store subject DN
            subject_dn = deployer.mdict['pki_%s_subject_dn' % deploy_tag]
            subsystem.config['preop.cert.%s.dn' % config_tag] = subject_dn

            keytype = deployer.mdict['pki_%s_key_type' % deploy_tag]
            subsystem.config['preop.cert.%s.keytype' % config_tag] = keytype

            keyalgorithm = deployer.mdict['pki_%s_key_algorithm' % deploy_tag]
            subsystem.config['preop.cert.%s.keyalgorithm' % config_tag] = keyalgorithm

            signingalgorithm = deployer.mdict.get(
                'pki_%s_signing_algorithm' % deploy_tag, keyalgorithm)
            subsystem.config['preop.cert.%s.signingalgorithm' % config_tag] = signingalgorithm

            # TODO: move more system cert params here

        # If specified in the deployment parameter, add generic CA signing cert
        # extension parameters into the CS.cfg. Generic extension for other
        # system certs can be added directly into CS.cfg after before the
        # configuration step.

        if subsystem.type == 'CA':
            if deployer.configuration_file.add_req_ext:

                subsystem.config['preop.cert.signing.ext.oid'] = \
                    deployer.configuration_file.req_ext_oid
                subsystem.config['preop.cert.signing.ext.data'] = \
                    deployer.configuration_file.req_ext_data
                subsystem.config['preop.cert.signing.ext.critical'] = \
                    deployer.configuration_file.req_ext_critical.lower()

            if deployer.configuration_file.req_ski:
                subsystem.config['preop.cert.signing.subject_key_id'] = \
                    deployer.configuration_file.req_ski

        if subsystem.type == 'KRA':
            if deployer.configuration_file.clone:

                token = subsystem.config['preop.module.token']
                if pki.nssdb.normalize_token(token):

                    storage_subsystem = subsystem.config['preop.cert.storage.subsystem']
                    storage_nickname = subsystem.config['preop.cert.storage.nickname']
                    transport_nickname = subsystem.config['preop.cert.transport.nickname']

                    subsystem.config['%s.storageUnit.hardware' % storage_subsystem] = token
                    subsystem.config['%s.storageUnit.nickName' % storage_subsystem] = \
                        token + ':' + storage_nickname
                    subsystem.config['%s.transportUnit.nickName' % storage_subsystem] = \
                        token + ':' + transport_nickname

        if deployer.configuration_file.clone:

            nickname = subsystem.config['%s.audit_signing.nickname' % subsystem.name]
            token = subsystem.config['%s.audit_signing.tokenname' % subsystem.name]

            if pki.nssdb.normalize_token(token):
                nickname = token + ':' + nickname

            subsystem.config['log.instance.SignedAudit.signedAuditCertNickname'] = nickname

        subsystem.save()

        # Place 'slightly' less restrictive permissions on
        # the top-level client directory ONLY

        deployer.directory.create(
            deployer.mdict['pki_client_subsystem_dir'],
            uid=0, gid=0,
            perms=config.PKI_DEPLOYMENT_DEFAULT_CLIENT_DIR_PERMISSIONS)

        # Since 'certutil' does NOT strip the 'token=' portion of
        # the 'token=password' entries, create a client password file
        # which ONLY contains the 'password' for the purposes of
        # allowing 'certutil' to generate the security databases

        logger.info('Creating password file: %s', deployer.mdict['pki_client_password_conf'])
        deployer.password.create_password_conf(
            deployer.mdict['pki_client_password_conf'],
            deployer.mdict['pki_client_database_password'], pin_sans_token=True)

        deployer.file.modify(
            deployer.mdict['pki_client_password_conf'],
            uid=0, gid=0)

        # Similarly, create a simple password file containing the
        # PKCS #12 password used when exporting the 'Admin Certificate'
        # into a PKCS #12 file

        deployer.password.create_client_pkcs12_password_conf(
            deployer.mdict['pki_client_pkcs12_password_conf'])

        deployer.file.modify(deployer.mdict['pki_client_pkcs12_password_conf'])

        pki.util.makedirs(deployer.mdict['pki_client_database_dir'], force=True)

        deployer.certutil.create_security_databases(
            deployer.mdict['pki_client_database_dir'],
            password_file=deployer.mdict['pki_client_password_conf'])

    def update_external_certs_conf(self, external_path, deployer):
        external_certs = pki.server.instance.PKIInstance.read_external_certs(
            external_path)

        if len(external_certs) > 0:
            deployer.instance.load_external_certs(
                os.path.join(deployer.mdict['pki_instance_configuration_path'],
                             'external_certs.conf')
            )

            for cert in external_certs:
                deployer.instance.add_external_cert(cert.nickname, cert.token)

    def destroy(self, deployer):

        # if this is not the last subsystem, skip
        if len(deployer.instance.tomcat_instance_subsystems()) > 0:
            return

        if deployer.directory.exists(deployer.mdict['pki_client_dir']):
            logger.info('Removing %s', deployer.mdict['pki_client_dir'])
            pki.util.rmtree(deployer.mdict['pki_client_dir'])

        logger.info('Removing %s', deployer.mdict['pki_server_database_path'])
        pki.util.rmtree(deployer.mdict['pki_server_database_path'])

        logger.info('Removing %s', deployer.mdict['pki_shared_password_conf'])
        pki.util.remove(deployer.mdict['pki_shared_password_conf'])
