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

            url = 'https://' + host.Hostname + ':' + host.SecurePort

            try:
                status = self.get_status(
                    host.Hostname,
                    host.SecurePort,
                    '/kra/admin/kra/getStatus')

                logger.info('KRA at %s is %s', url, status)

                if status != 'running':
                    raise Exception('KRA at %s is %s' % (url, status))

            except Exception as e:
                logger.error('Unable to reach KRA at %s: %s', url, e)
                raise Exception('Unable to reach KRA at %s: %s' % (url, e))

    def check_ocsp_clones(self):
        for host in self.clone_ocsps:

            url = 'https://' + host.Hostname + ':' + host.SecurePort

            try:
                status = self.get_status(
                    host.Hostname,
                    host.SecurePort,
                    '/ocsp/admin/ocsp/getStatus')

                logger.info('OCSP at %s is %s', url, status)

                if status != 'running':
                    raise Exception('OCSP at %s is %s' % (url, status))

            except Exception as e:
                logger.error('Unable to reach OCSP at %s: %s', url, e)
                raise Exception('Unable to reach OCSP at %s: %s' % (url, e))

    def check_tks_clones(self):
        for host in self.clone_tkss:

            url = 'https://' + host.Hostname + ':' + host.SecurePort

            try:
                status = self.get_status(
                    host.Hostname,
                    host.SecurePort,
                    '/tks/admin/tks/getStatus')

                logger.info('TKS at %s is %s', url, status)

                if status != 'running':
                    raise Exception('TKS at %s is %s' % (url, status))

            except Exception as e:
                logger.error('Unable to reach TKS at %s: %s', url, e)
                raise Exception('Unable to reach TKS at %s: %s' % (url, e))

    def check_tps_clones(self):
        for host in self.clone_tpss:

            url = 'https://' + host.Hostname + ':' + host.SecurePort

            try:
                status = self.get_status(
                    host.Hostname,
                    host.SecurePort,
                    '/tps/admin/tps/getStatus')

                logger.info('TPS at %s is %s', url, status)

                if status != 'running':
                    raise Exception('TPS at %s is %s' % (url, status))

            except Exception as e:
                logger.error('Unable to reach TPS at %s: %s', url, e)
                raise Exception('Unable to reach TPS at %s: %s' % (url, e))

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
