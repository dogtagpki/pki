#!/usr/bin/python -t
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

# PKI Deployment Imports
import pkiconfig as config
from pkiconfig import pki_master_dict as master
from pkiconfig import pki_sensitive_dict as sensitive
import pkihelper as util
import pkimessages as log
import pkiscriptlet


# PKI Deployment Security Databases Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self):
        config.pki_log.info(log.SECURITY_DATABASES_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        if not config.pki_dry_run_flag:
            util.password.create_password_conf(
                master['pki_shared_password_conf'],
                sensitive['pki_pin'])
            # Since 'certutil' does NOT strip the 'token=' portion of
            # the 'token=password' entries, create a temporary server 'pfile'
            # which ONLY contains the 'password' for the purposes of
            # allowing 'certutil' to generate the security databases
            util.password.create_password_conf(
                master['pki_shared_pfile'],
                sensitive['pki_pin'], pin_sans_token=True)
            util.file.modify(master['pki_shared_password_conf'])
            util.certutil.create_security_databases(
                master['pki_database_path'],
                master['pki_cert_database'],
                master['pki_key_database'],
                master['pki_secmod_database'],
                password_file=master['pki_shared_pfile'])
            util.file.modify(master['pki_cert_database'], perms=\
                config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)
            util.file.modify(master['pki_key_database'], perms=\
                config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)
            util.file.modify(master['pki_secmod_database'], perms=\
                config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)
            rv = util.certutil.verify_certificate_exists(
                     master['pki_database_path'],
                     master['pki_cert_database'],
                     master['pki_key_database'],
                     master['pki_secmod_database'],
                     master['pki_self_signed_token'],
                     master['pki_self_signed_nickname'],
                     password_file=master['pki_shared_pfile'])
            if not rv:
                util.file.generate_noise_file(
                    master['pki_self_signed_noise_file'],
                    master['pki_self_signed_noise_bytes'])
                util.certutil.generate_self_signed_certificate(
                    master['pki_database_path'],
                    master['pki_cert_database'],
                    master['pki_key_database'],
                    master['pki_secmod_database'],
                    master['pki_self_signed_token'],
                    master['pki_self_signed_nickname'],
                    master['pki_self_signed_subject'],
                    master['pki_self_signed_serial_number'],
                    master['pki_self_signed_validity_period'],
                    master['pki_self_signed_issuer_name'],
                    master['pki_self_signed_trustargs'],
                    master['pki_self_signed_noise_file'],
                    password_file=master['pki_shared_pfile'])
                # Delete the temporary 'noise' file
                util.file.delete(master['pki_self_signed_noise_file'])
            # Delete the temporary 'pfile'
            util.file.delete(master['pki_shared_pfile'])
        else:
            util.password.create_password_conf(
                master['pki_shared_password_conf'],
                sensitive['pki_pin'])
            # Since 'certutil' does NOT strip the 'token=' portion of
            # the 'token=password' entries, create a temporary server 'pfile'
            # which ONLY contains the 'password' for the purposes of
            # allowing 'certutil' to generate the security databases
            util.password.create_password_conf(
                master['pki_shared_pfile'],
                sensitive['pki_pin'], pin_sans_token=True)
            util.certutil.create_security_databases(
                master['pki_database_path'],
                master['pki_cert_database'],
                master['pki_key_database'],
                master['pki_secmod_database'],
                password_file=master['pki_shared_pfile'])
            rv = util.certutil.verify_certificate_exists(
                     master['pki_database_path'],
                     master['pki_cert_database'],
                     master['pki_key_database'],
                     master['pki_secmod_database'],
                     master['pki_self_signed_token'],
                     master['pki_self_signed_nickname'],
                     password_file=master['pki_shared_pfile'])
            if not rv:
                util.file.generate_noise_file(
                    master['pki_self_signed_noise_file'],
                    master['pki_self_signed_noise_bytes'])
                util.certutil.generate_self_signed_certificate(
                    master['pki_database_path'],
                    master['pki_cert_database'],
                    master['pki_key_database'],
                    master['pki_secmod_database'],
                    master['pki_self_signed_token'],
                    master['pki_self_signed_nickname'],
                    master['pki_self_signed_subject'],
                    master['pki_self_signed_serial_number'],
                    master['pki_self_signed_validity_period'],
                    master['pki_self_signed_issuer_name'],
                    master['pki_self_signed_trustargs'],
                    master['pki_self_signed_noise_file'],
                    password_file=master['pki_shared_pfile'])
                # Delete the temporary 'noise' file
                util.file.delete(master['pki_self_signed_noise_file'])
            # Delete the temporary 'pfile'
            util.file.delete(master['pki_shared_pfile'])
        return self.rv

    def respawn(self):
        config.pki_log.info(log.SECURITY_DATABASES_RESPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        util.file.modify(master['pki_shared_password_conf'])
        util.file.modify(master['pki_cert_database'],
            perms=config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)
        util.file.modify(master['pki_key_database'],
            perms=config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)
        util.file.modify(master['pki_secmod_database'],
            perms=config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)
        return self.rv

    def destroy(self):
        config.pki_log.info(log.SECURITY_DATABASES_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        if not config.pki_dry_run_flag:
            if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
               util.instance.apache_instances() == 0:
                util.file.delete(master['pki_cert_database'])
                util.file.delete(master['pki_key_database'])
                util.file.delete(master['pki_secmod_database'])
                util.file.delete(master['pki_shared_password_conf'])
            elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
                 util.instance.tomcat_instances() == 0:
                util.file.delete(master['pki_cert_database'])
                util.file.delete(master['pki_key_database'])
                util.file.delete(master['pki_secmod_database'])
                util.file.delete(master['pki_shared_password_conf'])
        else:
            # ALWAYS display correct information (even during dry_run)
            if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
               util.instance.apache_instances() == 1:
                util.file.delete(master['pki_cert_database'])
                util.file.delete(master['pki_key_database'])
                util.file.delete(master['pki_secmod_database'])
                util.file.delete(master['pki_shared_password_conf'])
            elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
                 util.instance.tomcat_instances() == 1:
                util.file.delete(master['pki_cert_database'])
                util.file.delete(master['pki_key_database'])
                util.file.delete(master['pki_secmod_database'])
                util.file.delete(master['pki_shared_password_conf'])
        return self.rv
