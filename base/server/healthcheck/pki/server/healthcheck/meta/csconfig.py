# Authors:
#     Rob Crittenden <rcrit@redhat.com>
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import logging
from contextlib import contextmanager

from pki.server.healthcheck.meta.plugin import MetaPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants

from pki.server.instance import PKIInstance

logger = logging.getLogger(__name__)


def compare_nssdb_with_cs(class_instance, subsystem, cert_tag):
    """
    Check whether the System Certs in NSSDB match with certs in CS.cfg

    :param class_instance: Reporting Class Instance
    :type class_instance: object
    :param subsystem: Subsystem
    :type subsystem: pki.server.subsystem.PKISubsystem
    :param cert_tag: Certificate tag name
    :type cert_tag: str
    :return: Result object with prefilled args
    :rtype: Result
    """

    # Generate cert_id for logging purpose
    cert_id = '{}_{}'.format(subsystem.name, cert_tag)

    # Load cert from CS
    cert = subsystem.get_cert_info(cert_tag)
    cert_cs = cert['data']

    # Load cert from NSSDB
    with nssdb_connection(subsystem.instance) as nssdb:
        try:
            # Retrieve the nickname and token from CS.cfg and then load
            # the corresponding cert from NSSDB
            cert_nssdb = nssdb.get_cert(
                nickname=cert['nickname'],
                token=cert['token'],
                output_format='base64'
            )
        except Exception as e:  # pylint: disable=broad-except
            logger.debug('Unable to load cert from NSSDB: %s', str(e))
            return Result(class_instance, constants.ERROR,
                          key=cert_id,
                          nssdbDir=subsystem.instance.nssdb_dir,
                          msg='Unable to load cert from NSSDB: %s' % str(e))

    # Compare whether the certs match
    if cert_nssdb != cert_cs:
        directive = '%s.%s.cert' % (subsystem.name, cert_tag)
        return Result(class_instance, constants.ERROR,
                      key=cert_id,
                      nickname=cert['nickname'],
                      directive=directive,
                      configfile=subsystem.cs_conf,
                      msg='Certificate \'%s\' does not match the value '
                          'of %s in %s' % (cert['nickname'],
                                           directive,
                                           subsystem.cs_conf))
    else:
        return Result(class_instance, constants.SUCCESS,
                      key=cert_id,
                      configfile=subsystem.cs_conf)


@registry
class CADogtagCertsConfigCheck(MetaPlugin):
    """
    Compare the cert blob in the NSS database to that stored in CA's CS.cfg
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
            logger.info("No CA configured, skipping dogtag config check")
            return

        cert_nicknames = [
            'sslserver',
            'subsystem',
            'audit_signing',
            'ocsp_signing',
            'signing'
        ]

        # Run the sync check
        for cert_tag in cert_nicknames:
            yield compare_nssdb_with_cs(class_instance=self,
                                        subsystem=ca,
                                        cert_tag=cert_tag)


@registry
class KRADogtagCertsConfigCheck(MetaPlugin):
    """
    Compare the cert blob in the NSS database to that stored in KRA's CS.cfg
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
            logger.info("No KRA configured, skipping dogtag config check")
            return

        cert_nicknames = [
            'sslserver',
            'subsystem',
            'transport',
            'storage',
            'audit_signing'
        ]

        # Run the sync check
        for cert_tag in cert_nicknames:
            yield compare_nssdb_with_cs(class_instance=self,
                                        subsystem=kra,
                                        cert_tag=cert_tag)


@registry
class OCSPDogtagCertsConfigCheck(MetaPlugin):
    """
    Compare the cert blob in the NSS database to that stored in OCSP's CS.cfg
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
            logger.info("No OCSP configured, skipping dogtag config check")
            return

        cert_nicknames = [
            'sslserver',
            'subsystem',
            'signing',
            'audit_signing'
        ]

        # Run the sync check
        for cert_tag in cert_nicknames:
            yield compare_nssdb_with_cs(class_instance=self,
                                        subsystem=ocsp,
                                        cert_tag=cert_tag)


@registry
class TKSDogtagCertsConfigCheck(MetaPlugin):
    """
    Compare the cert blob in the NSS database to that stored in TKS's CS.cfg
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
            logger.info("No TKS configured, skipping dogtag config check")
            return

        cert_nicknames = [
            'sslserver',
            'subsystem',
            'audit_signing'
        ]

        # Run the sync check
        for cert_tag in cert_nicknames:
            yield compare_nssdb_with_cs(class_instance=self,
                                        subsystem=tks,
                                        cert_tag=cert_tag)


@registry
class TPSDogtagCertsConfigCheck(MetaPlugin):
    """
    Compare the cert blob in the NSS database to that stored in TPS's CS.cfg
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
            logger.info("No TPS configured, skipping dogtag config check")
            return

        cert_nicknames = [
            'sslserver',
            'subsystem',
            'audit_signing'
        ]

        # Run the sync check
        for cert_tag in cert_nicknames:
            yield compare_nssdb_with_cs(class_instance=self,
                                        subsystem=tps,
                                        cert_tag=cert_tag)


@contextmanager
def nssdb_connection(instance):
    """Open a connection to nssdb containing System Certificates"""
    nssdb = instance.open_nssdb()
    try:
        yield nssdb
    finally:
        nssdb.close()
