# Authors:
#  Jack Magne    <jmagne@redhat.com> #
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import logging

from pki.server.healthcheck.clones.plugin import ClonesPlugin, registry
from pki.client import PKIConnection
from pki.cert import CertClient
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants

logger = logging.getLogger(__name__)


@registry
class ClonesConnectivyAndDataCheck(ClonesPlugin):
    """
    Assure master and clones within a  pki instance are reachable
    """
    def check_ca_clones(self):
        for host in self.clone_cas:
            cur_clone_msg = ' Host: ' + host.Hostname + ' Port: ' + host.SecurePort
            # Reach out and get some certs, to serve as a data and connectivity check
            try:
                connection = PKIConnection(protocol='https',
                                           hostname=host.Hostname,
                                           port=host.SecurePort,
                                           verify=False)

                cert_client = CertClient(connection)
                # get the first 3 in case we cant to make a sanity check of replicated data
                certs = cert_client.list_certs(size=3)

                if certs is not None and len(certs.cert_data_info_list) == 3:
                    logger.info('Cert data successfully obtained from clone.')
                else:
                    raise BaseException('CA clone problem reading data.' + cur_clone_msg)
            except BaseException as e:
                logger.error("Internal server error %s", e)
                raise BaseException('Internal error testing CA clone.' + cur_clone_msg)

        return

    def check_kra_clones(self):
        for host in self.clone_kras:
            cur_clone_msg = ' Host: ' + host.Hostname + ' Port: ' + host.SecurePort
            # Reach out and get some keys or requests , to serve as a data and connectivity check
            try:
                client_nick = self.security_domain.config.get('ca.connector.KRA.nickName')

                output = self.contact_subsystem_using_pki(
                    host.SecurePort, host.Hostname, client_nick,
                    self.passwd, self.db_dir, 'kra-key-show', ['0x01'])

                # check to see if we either got a key or a key not found exception
                # of which either will imply a successful connection
                if output is not None:
                    key_found = output.find('Key ID:')
                    key_not_found = output.find('KeyNotFoundException:')
                    if key_found >= 0:
                        logger.info('Key material found from kra clone.')

                    if key_not_found >= 0:
                        logger.info('key not found, possibly empty kra')

                    if key_not_found == -1 and key_found == -1:
                        logger.info('Failure to get key material from kra')
                        raise BaseException('KRA clone problem detected ' + cur_clone_msg)
                else:
                    raise BaseException('No data obtained from KRA clone.' + cur_clone_msg)

            except BaseException as e:
                logger.error("Internal error testing KRA clone. %s", e)
                raise BaseException('Internal error testing KRA clone.' + cur_clone_msg)

        return

    def check_ocsp_clones(self):
        for host in self.clone_ocsps:
            cur_clone_msg = ' Host: ' + host.Hostname + ' Port: ' + host.SecurePort
            # Reach out to the ocsp clones
            try:
                output = self.contact_subsystem_using_sslget(
                    host.SecurePort, host.Hostname, None,
                    self.passwd, self.db_dir, None, '/ocsp/admin/ocsp/getStatus')

                good_status = output.find('<State>1</State>')
                if good_status == -1:
                    raise BaseException('OCSP clone problem detected.' + cur_clone_msg)
                logger.info('good_status %s ', good_status)
            except BaseException as e:
                logger.error("Internal error testing OCSP clone.  %s", e)
                raise BaseException('Internal error testing OCSP clone.' + cur_clone_msg)

        return

    def check_tks_clones(self):
        for host in self.clone_tkss:
            cur_clone_msg = ' Host: ' + host.Hostname + ' Port: ' + host.SecurePort
            # Reach out to the tks clones
            try:
                output = self.contact_subsystem_using_sslget(
                    host.SecurePort, host.Hostname, None,
                    self.passwd, self.db_dir, None, '/tks/admin/tks/getStatus')

                good_status = output.find('<State>1</State>')
                if good_status == -1:
                    raise BaseException('TKS clone problem detected.' + cur_clone_msg)
                logger.info('good_status %s ', good_status)
            except BaseException as e:
                logger.error("Internal error testing TKS clone. %s", e)
                raise BaseException('Internal error testing TKS clone.' + cur_clone_msg)

        return

    def check_tps_clones(self):
        for host in self.clone_tpss:
            cur_clone_msg = ' Host: ' + host.Hostname + ' Port: ' + host.SecurePort
            # Reach out to the tps clones
            try:
                output = self.contact_subsystem_using_sslget(
                    host.SecurePort, host.Hostname, None,
                    self.passwd, self.db_dir, None, '/tps/admin/tps/getStatus')

                good_status = output.find('<State>1</State>')
                if good_status == -1:
                    raise BaseException('TPS clone problem detected.' + cur_clone_msg)
                logger.info('good_status  %s ', good_status)
            except BaseException as e:
                logger.error("Internal error testing TPS clone. %s", e)
                raise BaseException('Internal error testing TPS clone.' + cur_clone_msg)
        return

    @duration
    def check(self):
        logger.info("Entering ClonesConnectivityCheck : %s", self.instance.name)
        if not self.instance.exists():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         status='Invalid PKI instance: %s' % self.instance.name)
            return
        self.instance.load()

        security_domain_ca, sechost, secport = self.get_security_domain_ca()
        logger.info('security_domain_ca: %s ', security_domain_ca)

        logger.info('sechost %s secport %s ', sechost, secport)
        if security_domain_ca is None:
            yield Result(self, constants.SUCCESS,
                         status='Instance  not a security domain. %s' % self.instance.name)
        security_domain_data = self.get_security_domain_data(sechost, secport)

        if security_domain_data is not None:
            logger.info('About to check the subsystem clones')

            hard_msg = ' Clones tested successfully, or not present.'
            try:
                self.check_ca_clones()
                yield Result(self, constants.SUCCESS,
                             instance_name=self.instance.name,
                             status='CA' + hard_msg)

            except BaseException as e:
                yield Result(self, constants.ERROR,
                             status='ERROR:  %s' % self.instance.name + ' : ' + str(e))

            try:
                self.check_kra_clones()
                yield Result(self, constants.SUCCESS,
                             instance_name=self.instance.name,
                             status='KRA' + hard_msg)
            except BaseException as e:
                yield Result(self, constants.ERROR,
                             status='ERROR:  %s' % self.instance.name + ' : ' + str(e))

            try:
                self.check_ocsp_clones()
                yield Result(self, constants.SUCCESS,
                             instance_name=self.instance.name,
                             status='OCSP' + hard_msg)
            except BaseException as e:
                yield Result(self, constants.ERROR,
                             status='ERROR:  %s' % self.instance.name + ' : ' + str(e))

            try:
                self.check_tks_clones()
                yield Result(self, constants.SUCCESS,
                             instance_name=self.instance.name,
                             status='TKS' + hard_msg)
            except BaseException as e:
                yield Result(self, constants.ERROR,
                             status='ERROR:  %s' % self.instance.name + ' : ' + str(e))

            try:
                self.check_tps_clones()
                yield Result(self, constants.SUCCESS,
                             instance_name=self.instance.name,
                             status="TPS Clones tested successfully, or not present.")
            except BaseException as e:
                yield Result(self, constants.ERROR,
                             status='ERROR:  %s' % self.instance.name + ' : ' + str(e))
        else:
            yield Result(self, constants.SUCCESS,
                         instance_name=self.instance.name,
                         status='Instance has no security domain.')

        return
