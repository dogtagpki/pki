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


def check_cert_expiry_date(class_instance, cert):
    """
    Calculate the expiry status of the given cert

    :param class_instance: Reporting Class Instance
    :type class_instance: object
    :param cert: Certificate
    :type cert: dict
    :return: Result object with prefilled args
    :rtype: Result
    """

    # Get the current time in seconds
    current_time = int(round(time.time()))

    # Get the cert's expiry date in Milli seconds
    cert_expiry_time = cert.get('not_after')

    if cert_expiry_time is None:
        logger.critical("Unable to retrieve cert: %s", cert['nickname'])
        return Result(class_instance, constants.ERROR,
                      cert_id=cert['id'],
                      msg='Unable to get cert\'s expiry date')

    # Convert to seconds
    cert_expiry_time = cert_expiry_time / 1000

    # Calculate the difference in seconds
    delta_sec = cert_expiry_time - current_time

    # Calculate the number of days left/passed
    current_date = datetime.fromtimestamp(current_time)
    cert_expiry_date = datetime.fromtimestamp(cert_expiry_time)
    delta_days = (cert_expiry_date - current_date).days

    expiry_date_human = cert_expiry_date.strftime("%b %d %Y")

    if delta_sec <= 0:
        logger.error("Expired Cert: %s", cert['id'])
        return Result(class_instance, constants.ERROR,
                      cert_id=cert['id'],
                      expiry_date=expiry_date_human,
                      msg='Certificate has ALREADY EXPIRED')

    elif delta_days == 0 and delta_sec <= 86400:
        # Expiring in less than a day
        logger.warning("Expiring in a day: %s", cert['id'])
        return Result(class_instance, constants.WARNING,
                      cert_id=cert['id'],
                      msg='Expiring within next 24 hours')

    elif delta_days < int(class_instance.config.cert_expiration_days):
        # Expiring in a month
        logger.warning("Expiring in less than %s days: %s",
                       class_instance.config.cert_expiration_days,
                       cert['id'])
        return Result(class_instance, constants.WARNING,
                      cert_id=cert['id'],
                      expiry_date=expiry_date_human,
                      msg='Your certificate expires within %s days.' %
                          class_instance.config.cert_expiration_days)
    else:
        # Valid certificate
        logger.info("VALID certificate: %s", cert['id'])
        return Result(class_instance, constants.SUCCESS,
                      cert_id=cert['id'],
                      expiry_date=expiry_date_human)


@registry
class CASystemCertExpiryCheck(CertsPlugin):
    """
    Check the expiry of CA's system certs
    """

    @duration
    def check(self):
        if not self.instance.exists():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        ca = self.instance.get_subsystem('ca')

        if not ca:
            logger.info("No CA configured, skipping CA System Cert Expiry check")
            return

        audit_signing_nickname = ca.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        certs = ca.find_system_certs()

        for cert in certs:
            cert_id = cert['id']

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            yield check_cert_expiry_date(class_instance=self, cert=cert)


@registry
class KRASystemCertExpiryCheck(CertsPlugin):
    """
    Check the expiry of KRA's system certs
    """

    @duration
    def check(self):
        if not self.instance.exists():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        kra = self.instance.get_subsystem('kra')

        if not kra:
            logger.info("No KRA configured, skipping KRA System Cert Expiry check")
            return

        audit_signing_nickname = kra.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        certs = kra.find_system_certs()

        for cert in certs:
            cert_id = cert['id']

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            yield check_cert_expiry_date(class_instance=self, cert=cert)


@registry
class OCSPSystemCertExpiryCheck(CertsPlugin):
    """
    Check the expiry of OCSP's system certs
    """

    @duration
    def check(self):
        if not self.instance.exists():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        ocsp = self.instance.get_subsystem('ocsp')

        if not ocsp:
            logger.info("No OCSP configured, skipping OCSP System Cert Expiry check")
            return

        audit_signing_nickname = ocsp.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        certs = ocsp.find_system_certs()

        for cert in certs:
            cert_id = cert['id']

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            yield check_cert_expiry_date(class_instance=self, cert=cert)


@registry
class TKSSystemCertExpiryCheck(CertsPlugin):
    """
    Check the expiry of TKS's system certs
    """

    @duration
    def check(self):
        if not self.instance.exists():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        tks = self.instance.get_subsystem('tks')

        if not tks:
            logger.info("No TKS configured, skipping TKS System Cert Expiry check")
            return

        audit_signing_nickname = tks.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        certs = tks.find_system_certs()

        for cert in certs:
            cert_id = cert['id']

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            yield check_cert_expiry_date(class_instance=self, cert=cert)


@registry
class TPSSystemCertExpiryCheck(CertsPlugin):
    """
    Check the expiry of TPS's system certs
    """

    @duration
    def check(self):
        if not self.instance.exists():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        tps = self.instance.get_subsystem('tps')

        if not tps:
            logger.info("No TPS configured, skipping TPS System Cert Expiry check")
            return

        audit_signing_nickname = tps.config.get(
            'log.instance.SignedAudit.signedAuditCertNickname')

        certs = tps.find_system_certs()

        for cert in certs:
            cert_id = cert['id']

            # if audit signing nickname not configured, skip
            if cert_id == 'audit_signing' and not audit_signing_nickname:
                continue

            yield check_cert_expiry_date(class_instance=self, cert=cert)
