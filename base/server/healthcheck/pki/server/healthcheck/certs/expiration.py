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

        certs = ca.find_system_certs()

        for cert in certs:
            # Get current server date in millis and convert it into timestamp
            current_date = datetime.fromtimestamp(int(round(time.time())))

            # Cert's expiry date is returned in millis. Convert to timestamp
            expiry_date = datetime.fromtimestamp(cert.get('not_after') / 1000.0)

            # Throw an error if expiry date cannot be retrieved
            if expiry_date is None:
                logger.error("Expiry date of %s is None", cert['nickname'])
                yield Result(self, constants.ERROR,
                             nickname=cert['nickname'],
                             cert_id=cert['id'],
                             msg='Unable to get cert\'s expiry date')

                continue

            expiry_date_human = expiry_date.strftime("%b %d %Y")

            # Check if expired
            delta = (expiry_date - current_date).days
            if delta < 0:
                logger.error("Certificate has expired")
                yield Result(self, constants.ERROR,
                             nickname=cert['nickname'],
                             cert_id=cert['id'],
                             expiry_date=expiry_date_human,
                             no_of_days_passed=-delta,
                             msg='Certificate has ALREADY EXPIRED')
            else:
                # Check if certificate is expiring soon
                if delta < 30:
                    logger.warning("Certificate is expiring in less than a month")
                    yield Result(self, constants.WARNING,
                                 nickname=cert['nickname'],
                                 cert_id=cert['id'],
                                 expiry_date=expiry_date_human,
                                 remaining_days=delta,
                                 msg='Your certificate is ABOUT to expire. Certificate'
                                     ' expires in %s days' % delta)
                else:
                    logger.debug("Certificate is valid")
                    yield Result(self, constants.SUCCESS,
                                 cert_id=cert['id'],
                                 expiry_date=expiry_date_human,
                                 remaining_days=delta)


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

        certs = kra.find_system_certs()

        for cert in certs:
            # Get current server date in millis and convert it into timestamp
            current_date = datetime.fromtimestamp(int(round(time.time())))

            # Cert's expiry date is returned in millis. Convert to timestamp
            expiry_date = datetime.fromtimestamp(cert.get('not_after') / 1000.0)

            # Throw an error if expiry date cannot be retrieved
            if expiry_date is None:
                logger.error("Expiry date of %s is None", cert['nickname'])
                yield Result(self, constants.ERROR,
                             nickname=cert['nickname'],
                             cert_id=cert['id'],
                             msg='Unable to get cert\'s expiry date')

                continue

            expiry_date_human = expiry_date.strftime("%b %d %Y")

            # Check if expired
            delta = (expiry_date - current_date).days
            if delta < 0:
                logger.error("Certificate has expired")
                yield Result(self, constants.ERROR,
                             nickname=cert['nickname'],
                             cert_id=cert['id'],
                             expiry_date=expiry_date_human,
                             no_of_days_passed=-delta,
                             msg='Certificate has ALREADY EXPIRED')
            else:
                # Check if certificate is expiring soon
                if delta < 30:
                    logger.warning("Certificate is expiring in less than a month")
                    yield Result(self, constants.WARNING,
                                 nickname=cert['nickname'],
                                 cert_id=cert['id'],
                                 expiry_date=expiry_date_human,
                                 remaining_days=delta,
                                 msg='Your certificate is ABOUT to expire. Certificate'
                                     ' expires in %s days' % delta)
                else:
                    logger.debug("Certificate is valid")
                    yield Result(self, constants.SUCCESS,
                                 cert_id=cert['id'],
                                 expiry_date=expiry_date_human,
                                 remaining_days=delta)
