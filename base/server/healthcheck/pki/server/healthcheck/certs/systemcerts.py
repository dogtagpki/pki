# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import logging
import time
from datetime import datetime

from pki.server.healthcheck.certs.plugin import CertsPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants

logger = logging.getLogger(__name__)


def check_cert_expiry_date(
        plugin,
        cert_config,
        cert_info):
    '''
    Calculate the expiry status of the given cert

    :param plugin: Healthcheck plugin
    :type plugin: Plugin
    :param cert_config: Certificate config to validate
    :type cert_config: dict
    :param cert_info: Certificate info to validate
    :type cert_info: dict
    :return: Result object with prefilled args
    :rtype: Result
    '''

    # Get the current time in seconds
    current_time = int(round(time.time()))

    # Get the cert's expiry date in Milli seconds
    cert_expiry_time = cert_info.get('not_after')

    if cert_expiry_time is None:
        logger.error('Unable to retrieve cert: %s', cert_config['nickname'])
        return Result(plugin, constants.ERROR,
                      cert_id=cert_config['id'],
                      msg='Unable to get cert\'s expiry date')

    # Convert to seconds
    cert_expiry_time = cert_expiry_time / 1000

    # Calculate the difference in seconds
    delta_sec = cert_expiry_time - current_time

    # Calculate the number of days left/passed
    current_date = datetime.fromtimestamp(current_time)
    cert_expiry_date = datetime.fromtimestamp(cert_expiry_time)
    delta_days = (cert_expiry_date - current_date).days

    expiry_date_human = cert_expiry_date.strftime('%b %d %Y')

    if delta_sec <= 0:
        logger.error('Expired Cert: %s', cert_config['id'])
        return Result(plugin, constants.ERROR,
                      cert_id=cert_config['id'],
                      expiry_date=expiry_date_human,
                      msg='Certificate has ALREADY EXPIRED')

    elif delta_days == 0 and delta_sec <= 86400:
        # Expiring in less than a day
        logger.warning('Expiring in a day: %s', cert_config['id'])
        return Result(plugin, constants.WARNING,
                      cert_id=cert_config['id'],
                      msg='Expiring within next 24 hours')

    elif delta_days < int(plugin.config.cert_expiration_days):
        # Expiring in a month
        logger.warning('Expiring in less than %s days: %s',
                       plugin.config.cert_expiration_days,
                       cert_config['id'])
        return Result(plugin, constants.WARNING,
                      cert_id=cert_config['id'],
                      expiry_date=expiry_date_human,
                      msg='Your certificate expires within %s days.' %
                          plugin.config.cert_expiration_days)
    else:
        # Valid certificate
        logger.info('VALID certificate: %s', cert_config['id'])
        return Result(plugin, constants.SUCCESS,
                      cert_id=cert_config['id'],
                      expiry_date=expiry_date_human)


@registry
class CASystemCertCheck(CertsPlugin):
    '''
    Check CA system certs for trust flags and expiration
    '''
    @duration
    def check(self):
        if not self.instance.exists():
            logger.error('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        subsystem = self.instance.get_subsystem('ca')

        if not subsystem:
            logger.info('No CA configured, skipping CA system cert check')
            return

        # expected trust attributes
        expected_trust = {
            'signing': 'CTu,Cu,Cu',
            'ocsp_signing': 'u,u,u',
            'audit_signing': 'u,u,Pu',
            'sslserver': 'u,u,u',
            'subsystem': 'u,u,u'
        }

        audit_signing_nickname = subsystem.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        for cert_id in subsystem.get_subsystem_certs():
            cert_config = subsystem.get_system_cert_config(cert_id)

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            # check trust attributes
            try:
                cert_info = subsystem.get_system_cert_info(cert_id)
                cert_trust = cert_info['trust_flags']
            except Exception as e:  # pylint: disable=broad-except
                logger.debug('Unable to load cert from NSS database: %s', str(e))
                yield Result(self, constants.ERROR,
                             key=cert_id,
                             nssdbDir=self.instance.nssdb_dir,
                             msg='Unable to load cert from NSS database: %s' % str(e))
                yield check_cert_expiry_date(self, cert_config, cert_info)
                continue

            if cert_trust != expected_trust[cert_id]:
                yield Result(
                    self,
                    constants.ERROR,
                    cert_id=cert_id,
                    nickname=cert_config['nickname'],
                    token=cert_config['token'],
                    cert_trust=cert_trust,
                    msg='Incorrect trust attributes for %s. Got %s expected %s'
                        % (cert_config['nickname'], cert_trust, expected_trust[cert_id]))
            else:
                yield Result(
                    self,
                    constants.SUCCESS,
                    cert_id=cert_id,
                    nickname=cert_config['nickname'])

            # check expiration
            yield check_cert_expiry_date(self, cert_config, cert_info)


@registry
class KRASystemCertCheck(CertsPlugin):
    '''
    Check KRA system certs for trust flags and expiration
    '''
    @duration
    def check(self):
        if not self.instance.exists():
            logger.error('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        subsystem = self.instance.get_subsystem('kra')

        if not subsystem:
            logger.info('No KRA configured, skipping KRA system cert check')
            return

        # expected trust attributes
        expected_trust = {
            'sslserver': 'u,u,u',
            'subsystem': 'u,u,u',
            'transport': 'u,u,u',
            'storage': 'u,u,u',
            'audit_signing': 'u,u,Pu'
        }

        audit_signing_nickname = subsystem.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        for cert_id in subsystem.get_subsystem_certs():
            cert_config = subsystem.get_system_cert_config(cert_id)

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            # check trust attributes
            try:
                cert_info = subsystem.get_system_cert_info(cert_id)
                cert_trust = cert_info['trust_flags']
            except Exception as e:  # pylint: disable=broad-except
                logger.debug('Unable to load cert from NSS database: %s', str(e))
                yield Result(self, constants.ERROR,
                             key=cert_id,
                             nssdbDir=self.instance.nssdb_dir,
                             msg='Unable to load cert from NSS database: %s' % str(e))
                yield check_cert_expiry_date(self, cert_config, cert_info)
                continue

            if cert_trust != expected_trust[cert_id]:
                yield Result(
                    self,
                    constants.ERROR,
                    cert_id=cert_id,
                    nickname=cert_config['nickname'],
                    token=cert_config['token'],
                    cert_trust=cert_trust,
                    msg='Incorrect trust attributes for %s. Got %s expected %s'
                        % (cert_config['nickname'], cert_trust, expected_trust[cert_id]))
            else:
                yield Result(
                    self,
                    constants.SUCCESS,
                    cert_id=cert_id,
                    nickname=cert_config['nickname'])

            # check expiration
            yield check_cert_expiry_date(self, cert_config, cert_info)


@registry
class OCSPSystemCertCheck(CertsPlugin):
    '''
    Check OCSP system certs for trust flags and expiration
    '''
    @duration
    def check(self):
        if not self.instance.exists():
            logger.error('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        subsystem = self.instance.get_subsystem('ocsp')

        if not subsystem:
            logger.info('No OCSP configured, skipping OCSP system cert check')
            return

        # expected trust attributes
        expected_trust = {
            'sslserver': 'u,u,u',
            'subsystem': 'u,u,u',
            'signing': 'u,u,u',
            'audit_signing': 'u,u,Pu'
        }

        audit_signing_nickname = subsystem.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        for cert_id in subsystem.get_subsystem_certs():
            cert_config = subsystem.get_system_cert_config(cert_id)

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            # check trust attributes
            try:
                cert_info = subsystem.get_system_cert_info(cert_id)
                cert_trust = cert_info['trust_flags']
            except Exception as e:  # pylint: disable=broad-except
                logger.debug('Unable to load cert from NSS database: %s', str(e))
                yield Result(self, constants.ERROR,
                             key=cert_id,
                             nssdbDir=self.instance.nssdb_dir,
                             msg='Unable to load cert from NSS database: %s' % str(e))
                yield check_cert_expiry_date(self, cert_config, cert_info)
                continue

            if cert_trust != expected_trust[cert_id]:
                yield Result(
                    self,
                    constants.ERROR,
                    cert_id=cert_id,
                    nickname=cert_config['nickname'],
                    token=cert_config['token'],
                    cert_trust=cert_trust,
                    msg='Incorrect trust attributes for %s. Got %s expected %s'
                        % (cert_config['nickname'], cert_trust, expected_trust[cert_id]))
            else:
                yield Result(
                    self,
                    constants.SUCCESS,
                    cert_id=cert_id,
                    nickname=cert_config['nickname'])

            # check expiration
            yield check_cert_expiry_date(self, cert_config, cert_info)


@registry
class TKSSystemCertCheck(CertsPlugin):
    '''
    Check TKS system certs for trust flags and expiration
    '''
    @duration
    def check(self):
        if not self.instance.exists():
            logger.error('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        subsystem = self.instance.get_subsystem('tks')

        if not subsystem:
            logger.info('No TKS configured, skipping TKS system cert check')
            return

        # expected trust attributes
        expected_trust = {
            'sslserver': 'u,u,u',
            'subsystem': 'u,u,u',
            'audit_signing': 'u,u,Pu'
        }

        audit_signing_nickname = subsystem.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        for cert_id in subsystem.get_subsystem_certs():
            cert_config = subsystem.get_system_cert_config(cert_id)

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            # check trust attributes
            try:
                cert_info = subsystem.get_system_cert_info(cert_id)
                cert_trust = cert_info['trust_flags']
            except Exception as e:  # pylint: disable=broad-except
                logger.debug('Unable to load cert from NSS database: %s', str(e))
                yield Result(self, constants.ERROR,
                             key=cert_id,
                             nssdbDir=self.instance.nssdb_dir,
                             msg='Unable to load cert from NSS database: %s' % str(e))
                yield check_cert_expiry_date(self, cert_config, cert_info)
                continue

            if cert_trust != expected_trust[cert_id]:
                yield Result(
                    self,
                    constants.ERROR,
                    cert_id=cert_id,
                    nickname=cert_config['nickname'],
                    token=cert_config['token'],
                    cert_trust=cert_trust,
                    msg='Incorrect trust attributes for %s. Got %s expected %s'
                        % (cert_config['nickname'], cert_trust, expected_trust[cert_id]))
            else:
                yield Result(
                    self,
                    constants.SUCCESS,
                    cert_id=cert_id,
                    nickname=cert_config['nickname'])

            # check expiration
            yield check_cert_expiry_date(self, cert_config, cert_info)


@registry
class TPSSystemCertCheck(CertsPlugin):
    '''
    Check TPS system certs for trust flags and expiration
    '''
    @duration
    def check(self):
        if not self.instance.exists():
            logger.error('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        subsystem = self.instance.get_subsystem('tps')

        if not subsystem:
            logger.info('No TPS configured, skipping TPS system cert check')
            return

        # expected trust attributes
        expected_trust = {
            'sslserver': 'u,u,u',
            'subsystem': 'u,u,u',
            'audit_signing': 'u,u,Pu'
        }

        audit_signing_nickname = subsystem.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        for cert_id in subsystem.get_subsystem_certs():
            cert_config = subsystem.get_system_cert_config(cert_id)

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            # check trust attributes
            try:
                cert_info = subsystem.get_system_cert_info(cert_id)
                cert_trust = cert_info['trust_flags']
            except Exception as e:  # pylint: disable=broad-except
                logger.debug('Unable to load cert from NSS database: %s', str(e))
                yield Result(self, constants.ERROR,
                             key=cert_id,
                             nssdbDir=self.instance.nssdb_dir,
                             msg='Unable to load cert from NSS database: %s' % str(e))
                yield check_cert_expiry_date(self, cert_config, cert_info)
                continue

            if cert_trust != expected_trust[cert_id]:
                yield Result(
                    self,
                    constants.ERROR,
                    cert_id=cert_id,
                    nickname=cert_config['nickname'],
                    token=cert_config['token'],
                    cert_trust=cert_trust,
                    msg='Incorrect trust attributes for %s. Got %s expected %s'
                        % (cert_config['nickname'], cert_trust, expected_trust[cert_id]))
            else:
                yield Result(
                    self,
                    constants.SUCCESS,
                    cert_id=cert_id,
                    nickname=cert_config['nickname'])

            # check expiration
            yield check_cert_expiry_date(self, cert_config, cert_info)
