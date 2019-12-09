#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging
from contextlib import contextmanager

from pkihealthcheck.pki.plugin import CSPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants

from pki.server import PKIServer

logger = logging.getLogger()


@registry
class DogtagCertsConfigCheck(CSPlugin):
    """
    Compare the cert blob in the NSS database to that stored in CS.cfg
    """
    @duration
    def check(self):
        if not self.instance.is_valid():
            logging.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        ca = self.instance.get_subsystem('ca')

        if not ca:
            logger.debug("No CA configured, skipping dogtag config check")
            return

        cert_nicknames = [
            'sslserver',
            'subsystem',
            'ca_audit_signing',
            'ca_ocsp_signing',
            'ca_signing'
        ]

        kra = self.instance.get_subsystem('kra')

        if kra:
            logger.debug("KRA is installed, adding corresponding system certs")

            cert_nicknames.append('kra_transport')
            cert_nicknames.append('kra_storage')
            cert_nicknames.append('kra_audit_signing')

        cert_nssdb = None

        # Run the sync check
        for cert_id in cert_nicknames:
            subsystem_name, cert_tag = PKIServer.split_cert_id(cert_id)

            if not subsystem_name or subsystem_name == 'ca':
                subsystem = ca
            elif subsystem_name == 'kra':
                subsystem = kra
            else:
                logger.error('Subsystem not supported yet')
                yield Result(self, constants.ERROR,
                             key=cert_id,
                             subsystem=subsystem_name,
                             msg='Subsystem not supported yet: %s' % subsystem_name)
                continue

            # Load cert from CS
            cert = subsystem.get_cert_info(cert_tag)
            cert_cs = cert['data']

            # Load cert from NSSDB
            with nssdb_connection(self.instance) as nssdb:
                try:
                    # Retrieve the nickname and token from CS.cfg and then load
                    # the corresponding cert from NSSDB
                    cert_nssdb = nssdb.get_cert(
                        nickname=cert['nickname'],
                        token=cert['token'],
                        output_format='base64'
                    )
                except Exception as e:
                    logger.debug('Unable to load cert from NSSDB: %s' % str(e))
                    yield Result(self, constants.ERROR,
                                 key=cert_id,
                                 nssdbDir=self.instance.nssdb_dir,
                                 msg='Unable to load cert from NSSDB: %s' % str(e))
                    continue

            # Compare whether the certs match
            if cert_nssdb != cert_cs:
                directive = '%s.%s.cert' % (subsystem.name, cert_tag)
                yield Result(self, constants.ERROR,
                             key=cert_id,
                             nickname=cert['nickname'],
                             directive=directive,
                             configfile=subsystem.cs_conf,
                             msg='Certificate \'%s\' does not match the value '
                                 'of %s in %s' % (cert['nickname'],
                                                  directive,
                                                  subsystem.cs_conf))
            else:
                yield Result(self, constants.SUCCESS,
                             key=cert_id,
                             configfile=subsystem.cs_conf)


@contextmanager
def nssdb_connection(instance):
    """Open a connection to nssdb containing System Certificates"""
    nssdb = instance.open_nssdb()
    try:
        yield nssdb
    finally:
        nssdb.close()
