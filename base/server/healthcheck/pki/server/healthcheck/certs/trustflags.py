# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import logging
from contextlib import contextmanager

from pki.server.healthcheck.certs.plugin import CertsPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants

logger = logging.getLogger(__name__)


@registry
class CASystemCertTrustFlagCheck(CertsPlugin):
    """
    Compare the NSS trust for the CA certs to a known good value
    """
    @duration
    def check(self):
        if not self.instance.exists():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        # Make a list of known good trust flags for ALL system certs
        expected_trust = {
            'signing': 'CTu,Cu,Cu',
            'ocsp_signing': 'u,u,u',
            'audit_signing': 'u,u,Pu',
            'sslserver': 'u,u,u',
            'subsystem': 'u,u,u'
        }

        ca = self.instance.get_subsystem('ca')

        if not ca:
            logger.info("No CA configured, skipping CA System Cert Trust Flag check")
            return

        audit_signing_nickname = ca.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        certs = ca.find_system_certs()

        # Iterate on CA's all system certificate to check with list of expected trust flags
        for cert in certs:
            cert_id = cert['id']

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            # Load cert trust from NSSDB
            with nssdb_connection(self.instance) as nssdb:
                try:
                    cert_trust = nssdb.get_trust(
                        nickname=cert['nickname'],
                        token=cert['token']
                    )
                except Exception as e:  # pylint: disable=broad-except
                    logger.debug('Unable to load cert from NSSDB: %s', str(e))
                    yield Result(self, constants.ERROR,
                                 key=cert_id,
                                 nssdbDir=self.instance.nssdb_dir,
                                 msg='Unable to load cert from NSSDB: %s' % str(e))
                    continue
            if cert_trust != expected_trust[cert_id]:
                yield Result(self, constants.ERROR,
                             cert_id=cert_id,
                             nickname=cert['nickname'],
                             token=cert['token'],
                             cert_trust=cert_trust,
                             msg='Incorrect NSS trust for %s. Got %s expected %s'
                             % (cert['nickname'], cert_trust, expected_trust[cert_id]))
            else:
                yield Result(self, constants.SUCCESS,
                             cert_id=cert_id,
                             nickname=cert['nickname'])


@registry
class KRASystemCertTrustFlagCheck(CertsPlugin):
    """
    Compare the NSS trust for the KRA certs to a known good value
    """
    @duration
    def check(self):
        if not self.instance.exists():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        # Make a list of known good trust flags for ALL system certs
        expected_trust = {
            'sslserver': 'u,u,u',
            'subsystem': 'u,u,u',
            'transport': 'u,u,u',
            'storage': 'u,u,u',
            'audit_signing': 'u,u,Pu'
        }

        kra = self.instance.get_subsystem('kra')

        if not kra:
            logger.info("No KRA configured, skipping KRA System Cert Trust Flag check")
            return

        audit_signing_nickname = kra.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        certs = kra.find_system_certs()

        # Iterate on KRA's all system certificate to check with list of expected trust flags
        for cert in certs:
            cert_id = cert['id']

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            # Load cert trust from NSSDB
            with nssdb_connection(self.instance) as nssdb:
                try:
                    cert_trust = nssdb.get_trust(
                        nickname=cert['nickname'],
                        token=cert['token']
                    )
                except Exception as e:  # pylint: disable=broad-except
                    logger.debug('Unable to load cert from NSSDB: %s', str(e))
                    yield Result(self, constants.ERROR,
                                 key=cert_id,
                                 nssdbDir=self.instance.nssdb_dir,
                                 msg='Unable to load cert from NSSDB: %s' % str(e))
                    continue
            if cert_trust != expected_trust[cert_id]:
                yield Result(self, constants.ERROR,
                             cert_id=cert_id,
                             nickname=cert['nickname'],
                             token=cert['token'],
                             cert_trust=cert_trust,
                             msg='Incorrect NSS trust for %s. Got %s expected %s'
                                 % (cert['nickname'], cert_trust, expected_trust[cert_id]))
            else:
                yield Result(self, constants.SUCCESS,
                             cert_id=cert_id,
                             nickname=cert['nickname'])


@registry
class OCSPSystemCertTrustFlagCheck(CertsPlugin):
    """
    Compare the NSS trust for the OCSP certs to a known good value
    """
    @duration
    def check(self):
        if not self.instance.exists():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        # Make a list of known good trust flags for ALL system certs
        expected_trust = {
            'sslserver': 'u,u,u',
            'subsystem': 'u,u,u',
            'signing': 'u,u,u',
            'audit_signing': 'u,u,Pu'
        }

        ocsp = self.instance.get_subsystem('ocsp')

        if not ocsp:
            logger.info("No OCSP configured, skipping OCSP System Cert Trust Flag check")
            return

        audit_signing_nickname = ocsp.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        certs = ocsp.find_system_certs()

        # Iterate on OCSP's all system certificate to check with list of expected trust flags
        for cert in certs:
            cert_id = cert['id']

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            # Load cert trust from NSSDB
            with nssdb_connection(self.instance) as nssdb:
                try:
                    cert_trust = nssdb.get_trust(
                        nickname=cert['nickname'],
                        token=cert['token']
                    )
                except Exception as e:  # pylint: disable=broad-except
                    logger.debug('Unable to load cert from NSSDB: %s', str(e))
                    yield Result(self, constants.ERROR,
                                 key=cert_id,
                                 nssdbDir=self.instance.nssdb_dir,
                                 msg='Unable to load cert from NSSDB: %s' % str(e))
                    continue
            if cert_trust != expected_trust[cert_id]:
                yield Result(self, constants.ERROR,
                             cert_id=cert_id,
                             nickname=cert['nickname'],
                             token=cert['token'],
                             cert_trust=cert_trust,
                             msg='Incorrect NSS trust for %s. Got %s expected %s'
                                 % (cert['nickname'], cert_trust, expected_trust[cert_id]))
            else:
                yield Result(self, constants.SUCCESS,
                             cert_id=cert_id,
                             nickname=cert['nickname'])


@registry
class TKSSystemCertTrustFlagCheck(CertsPlugin):
    """
    Compare the NSS trust for the TKS certs to a known good value
    """
    @duration
    def check(self):
        if not self.instance.exists():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        # Make a list of known good trust flags for ALL system certs
        expected_trust = {
            'sslserver': 'u,u,u',
            'subsystem': 'u,u,u',
            'audit_signing': 'u,u,Pu'
        }

        tks = self.instance.get_subsystem('tks')

        if not tks:
            logger.info("No TKS configured, skipping TKS System Cert Trust Flag check")
            return

        audit_signing_nickname = tks.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        certs = tks.find_system_certs()

        # Iterate on TKS's all system certificate to check with list of expected trust flags
        for cert in certs:
            cert_id = cert['id']

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            # Load cert trust from NSSDB
            with nssdb_connection(self.instance) as nssdb:
                try:
                    cert_trust = nssdb.get_trust(
                        nickname=cert['nickname'],
                        token=cert['token']
                    )
                except Exception as e:  # pylint: disable=broad-except
                    logger.debug('Unable to load cert from NSSDB: %s', str(e))
                    yield Result(self, constants.ERROR,
                                 key=cert_id,
                                 nssdbDir=self.instance.nssdb_dir,
                                 msg='Unable to load cert from NSSDB: %s' % str(e))
                    continue
            if cert_trust != expected_trust[cert_id]:
                yield Result(self, constants.ERROR,
                             cert_id=cert_id,
                             nickname=cert['nickname'],
                             token=cert['token'],
                             cert_trust=cert_trust,
                             msg='Incorrect NSS trust for %s. Got %s expected %s'
                                 % (cert['nickname'], cert_trust, expected_trust[cert_id]))
            else:
                yield Result(self, constants.SUCCESS,
                             cert_id=cert_id,
                             nickname=cert['nickname'])


@registry
class TPSSystemCertTrustFlagCheck(CertsPlugin):
    """
    Compare the NSS trust for the TPS certs to a known good value
    """
    @duration
    def check(self):
        if not self.instance.exists():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        # Make a list of known good trust flags for ALL system certs
        expected_trust = {
            'sslserver': 'u,u,u',
            'subsystem': 'u,u,u',
            'audit_signing': 'u,u,Pu'
        }

        tps = self.instance.get_subsystem('tps')

        if not tps:
            logger.info("No TPS configured, skipping TPS System Cert Trust Flag check")
            return

        audit_signing_nickname = tps.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        certs = tps.find_system_certs()

        # Iterate on TPS's all system certificate to check with list of expected trust flags
        for cert in certs:
            cert_id = cert['id']

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            # Load cert trust from NSSDB
            with nssdb_connection(self.instance) as nssdb:
                try:
                    cert_trust = nssdb.get_trust(
                        nickname=cert['nickname'],
                        token=cert['token']
                    )
                except Exception as e:  # pylint: disable=broad-except
                    logger.debug('Unable to load cert from NSSDB: %s', str(e))
                    yield Result(self, constants.ERROR,
                                 key=cert_id,
                                 nssdbDir=self.instance.nssdb_dir,
                                 msg='Unable to load cert from NSSDB: %s' % str(e))
                    continue
            if cert_trust != expected_trust[cert_id]:
                yield Result(self, constants.ERROR,
                             cert_id=cert_id,
                             nickname=cert['nickname'],
                             token=cert['token'],
                             cert_trust=cert_trust,
                             msg='Incorrect NSS trust for %s. Got %s expected %s'
                                 % (cert['nickname'], cert_trust, expected_trust[cert_id]))
            else:
                yield Result(self, constants.SUCCESS,
                             cert_id=cert_id,
                             nickname=cert['nickname'])


@contextmanager
def nssdb_connection(instance):
    """Open a connection to nssdb containing System Certificates"""
    nssdb = instance.open_nssdb()
    try:
        yield nssdb
    finally:
        nssdb.close()
