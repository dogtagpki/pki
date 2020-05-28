import logging

from pki.server.healthcheck.meta.plugin import CSPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants
from pki.client import PKIConnection
from pki.cert import CertClient
from pki.systemcert import SystemCertClient

logger = logging.getLogger(__name__)


@registry
class DogtagCACertsConnectivityCheck(CSPlugin):
    """
    Test basic CA connectivity by using cert-find to fetch a cert
    """

    @duration
    def check(self):
        if not self.instance.is_valid():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        ca = self.instance.get_subsystem('ca')

        if not ca:
            logger.debug("No CA configured, skipping dogtag CA connectivity check")
            return

        try:
            # Make a plain HTTP GET request to /ca/admin/ca/getStatus REST api end point
            # and check if the CA is ready
            if ca.is_ready():
                logger.debug("CA instance is running")

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
                                     subject_dn=cert_info.subject_dn)
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

            else:
                yield Result(self, constants.CRITICAL,
                             msg='CA subsystem is down')

        except BaseException as e:
            logger.error("Internal server error %s", e)
            yield Result(self, constants.CRITICAL,
                         msg="Internal server error. Is your CA subsystem and "
                             "LDAP database up?",
                         instance_name=self.instance.name,
                         exception="%s" % e)


@registry
class DogtagKRAConnectivityCheck(CSPlugin):
    """
    Test basic KRA connectivity by trying to fetch the transport cert using REST endpoint.
    """

    @duration
    def check(self):
        if not self.instance.is_valid():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        kra = self.instance.get_subsystem('kra')

        if not kra:
            logger.debug("No KRA configured, skipping dogtag KRA connectivity check")
            return

        try:
            # Make a plain HTTP GET request to /kra/admin/kra/getStatus REST api end point
            # and check if the KRA is up
            if kra.is_ready():
                logger.info("KRA instance is running.")

                # Make a plain HTTP GET to retrieve KRA transport cert, to test that
                # the server is up AND is able to respond back
                connection = PKIConnection(protocol='https',
                                           hostname='localhost',
                                           port='8443')

                system_cert_client = SystemCertClient(connection)

                # This gets the KRA cert from CS.cfg via REST API. In future, the system
                # certs will be moved into LDAP. This means that even if LDAP is down
                # there will be a SUCCESSFUL response if KRA is running.
                transport_cert = system_cert_client.get_transport_cert()

                if transport_cert:

                    if transport_cert.serial_number:
                        logger.info("Serial number of retrieved transport cert: %s",
                                    transport_cert.serial_number)
                        yield Result(self, constants.SUCCESS,
                                     serial_number=transport_cert.serial_number,
                                     subject_dn=transport_cert.subject_dn)
                    else:
                        logger.info("Serial number cannot retrieved for transport cert: %s",
                                    transport_cert)
                        yield Result(self, constants.ERROR,
                                     msg="Unable to read serial number from retrieved cert",
                                     cert_info=transport_cert,
                                     serverURI=connection.serverURI,
                                     rest_path=system_cert_client.cert_url)
                else:
                    logger.info("Request was made but the transport cert cannot be retrieved")
                    yield Result(self, constants.ERROR,
                                 msg="KRA server is up. But, unable to retrieve transport cert",
                                 serverURI=connection.serverURI,
                                 rest_path=system_cert_client.cert_url)

            else:
                yield Result(self, constants.CRITICAL,
                             msg='KRA subsystem is down')

        except BaseException as e:
            logger.error("Internal server error %s", e)
            yield Result(self, constants.CRITICAL,
                         msg="Internal server error. Is your KRA subsystem and "
                             "LDAP database up?",
                         instance_name=self.instance.name,
                         exception="%s" % e)


@registry
class DogtagOCSPConnectivityCheck(CSPlugin):
    """
    Test basic OCSP connectivity by trying to hit REST api endpoint. Note that this
    test DOES NOT fetch any objects from LDAP. This only tests whether OCSP is running.
    """

    @duration
    def check(self):
        if not self.instance.is_valid():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        ocsp = self.instance.get_subsystem('ocsp')

        if not ocsp:
            logger.debug("No OCSP configured, skipping dogtag OCSP connectivity check")
            return

        try:
            # Make a plain HTTP GET request to /ocsp/admin/ocsp/getStatus REST api end point
            # and check if the OCSP is running
            if ocsp.is_ready():
                logger.info("OCSP instance is running.")
                yield Result(self, constants.SUCCESS,
                             instance_name=ocsp.instance.name,
                             subsystem_name=ocsp.name,
                             status="Running")
            else:
                logger.info("OCSP instance is down.")
                yield Result(self, constants.ERROR,
                             instance_name=ocsp.instance.name,
                             subsystem_name=ocsp.name,
                             status="Stopped")

        except BaseException as e:
            logger.error("Internal server error %s", e)
            yield Result(self, constants.CRITICAL,
                         msg="Internal server error. Is your OCSP subsystem and "
                             "LDAP database up?",
                         instance_name=self.instance.name,
                         exception="%s" % e)


@registry
class DogtagTKSConnectivityCheck(CSPlugin):
    """
    Test basic TKS connectivity by trying to hit REST api endpoint. Note that this
    test DOES NOT fetch any objects from LDAP. This only tests whether TKS is running.
    """

    @duration
    def check(self):
        if not self.instance.is_valid():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        tks = self.instance.get_subsystem('tks')

        if not tks:
            logger.debug("No TKS configured, skipping dogtag TKS connectivity check")
            return

        try:
            # Make a plain HTTP GET request to /tks/admin/tks/getStatus REST api end point
            # and check if the TKS is running
            if tks.is_ready():
                logger.info("TKS instance is running.")
                yield Result(self, constants.SUCCESS,
                             instance_name=tks.instance.name,
                             subsystem_name=tks.name,
                             status="Running")
            else:
                logger.info("TKS instance is down.")
                yield Result(self, constants.ERROR,
                             instance_name=tks.instance.name,
                             subsystem_name=tks.name,
                             status="Stopped")

        except BaseException as e:
            logger.error("Internal server error %s", e)
            yield Result(self, constants.CRITICAL,
                         msg="Internal server error. Is your TKS subsystem and "
                             "LDAP database up?",
                         instance_name=self.instance.name,
                         exception="%s" % e)


@registry
class DogtagTPSConnectivityCheck(CSPlugin):
    """
    Test basic TPS connectivity by trying to hit REST api endpoint. Note that this
    test DOES NOT fetch any objects from LDAP. This only tests whether TPS is running.
    """

    @duration
    def check(self):
        if not self.instance.is_valid():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        tps = self.instance.get_subsystem('tps')

        if not tps:
            logger.debug("No TPS configured, skipping dogtag TPS connectivity check")
            return

        try:
            # Make a plain HTTP GET request to /tps/admin/tps/getStatus REST api end point
            # and check if the TPS is running
            if tps.is_ready():
                logger.info("TPS instance is running.")
                yield Result(self, constants.SUCCESS,
                             instance_name=tps.instance.name,
                             subsystem_name=tps.name,
                             status="Running")
            else:
                logger.info("TPS instance is down.")
                yield Result(self, constants.ERROR,
                             instance_name=tps.instance.name,
                             subsystem_name=tps.name,
                             status="Stopped")

        except BaseException as e:
            logger.error("Internal server error %s", e)
            yield Result(self, constants.CRITICAL,
                         msg="Internal server error. Is your TPS subsystem and "
                             "LDAP database up?",
                         instance_name=self.instance.name,
                         exception="%s" % e)
