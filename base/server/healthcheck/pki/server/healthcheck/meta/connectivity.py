import logging

from pki.server.healthcheck.meta.plugin import CSPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants
from pki.client import PKIConnection
from pki.cert import CertClient

logger = logging.getLogger()


@registry
class DogtagCACertsConnectivityCheck(CSPlugin):
    """
    Test basic CA connectivity by using cert-find to fetch a cert
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
            logger.debug("No CA configured, skipping dogtag CA connectivity check")
            return

        # Make a plain HTTP GET request to /ca/admin/ca/getStatus REST api end point
        # and check if the CA is ready
        if ca.is_ready():
            logger.debug("CA instance is running")
            connection = None
            cert_client = None

            try:
                # Make a plain HTTP GET to "find" one certificate, to test that
                # the server is up AND is able to respond back
                connection = PKIConnection(protocol='https',
                                           hostname='localhost',
                                           port='8443')

                cert_client = CertClient(connection)
                cert = cert_client.list_certs(size=1)
                cert_info = cert.cert_data_info_list[0]
                if cert_info:
                    # All we care is whether the serial_number is not NONE
                    if cert_info.serial_number:
                        logger.info("Serial number of retrieved cert: %s", cert_info.serial_number)
                        yield Result(self, constants.SUCCESS,
                                     serial_number=cert_info.serial_number,
                                     subject_dn=cert_info.subject_dn,
                                     type=cert_info.type,
                                     status=cert_info.status)
                    else:
                        logger.info("Serial number cannot retrieved for cert: %s", cert_info)
                        yield Result(self, constants.ERROR,
                                     msg="Unable to read serial number from retrieved cert",
                                     cert_info=cert_info,
                                     serverURI=connection.serverURI,
                                     cert_url=cert_client.cert_url)
                else:
                    logger.info("Request was made but none of the certs were retrieved")
                    yield Result(self, constants.ERROR,
                                 msg="PKI server is up. But, unable to retrieve any certs",
                                 serverURI=connection.serverURI,
                                 rest_path=cert_client.cert_url)

            except BaseException as e:
                logger.error("Internal server error %s", e)
                yield Result(self, constants.CRITICAL,
                             msg="Internal server error. Is your PKI server and LDAP up?",
                             serverURI=connection.serverURI,
                             rest_path=cert_client.cert_url,
                             exception="%s" % e)
        else:
            yield Result(self, constants.CRITICAL,
                         msg='CA subsystem is down')
