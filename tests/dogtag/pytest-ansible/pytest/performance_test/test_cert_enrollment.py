"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Load Test client Server Side configuration
#   Steps :-
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Deepak Punia <dpunia@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from pki.client import PKIConnection
from pki.cert import CertClient
from timeit import default_timer as timer
import socket
import sys
import logging
import threading
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument("--hostname",
                    help="CA hostname (default: %s)" % socket.gethostname(),
                    default=socket.gethostname())
parser.add_argument("--port",
                    help="CA port number (default: 8443)",
                    default="8443")
parser.add_argument("--client-cert",
                    help="Path to admin certificate and key in PEM format")
parser.add_argument("--number-of-clients", "--clients",
                    help="Number of clients",
                    default=1,
                    type=int)
parser.add_argument("--number-of-tests-per-client", "--tests-per-client",
                    help="Number of tests per client",
                    default=1,
                    type=int)
parser.add_argument("--ca-cert-path", "--ca-cert",
                    help="Path to CA signing certificate in PEM format")
parser.add_argument("-v", "--verbose",
                    help="Run in verbose mode.",
                    action="store_true")
parser.add_argument("--debug",
                    help="Run in debug mode.",
                    action="store_true")

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(levelname)s: %(message)s')
args = parser.parse_args()


class cert_enroll(object):
    """
    #This class will enroll the certificate.
    """

    def __init__(self, id, sn_uid, cert_client):
        """
        Constructor
        """
        # Enrolling an user certificate

        inputs = dict()
        inputs['cert_request_type'] = 'pkcs10'
        inputs['cert_request'] = """-----BEGIN CERTIFICATE REQUEST-----
        MIIEnTCCAoUCAQAwWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMRAwDgYDVQQH
        DAdSYWxlaWdoMRUwEwYDVQQKDAxSZWQgSGF0IEluYy4xEzARBgNVBAMMClRlc3RT
        ZXJ2ZXIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDAsEgwOUFN9MpJ
        0kyXqbxtejDWh0m0+u9Dq3gcMGm6AUYggpIWsiIy+rBVSZfM3xj8Oj0vnMQGyhYa
        LsRku019g1M1gG2M7bLjxbABPmRqsrVVh6494TPSTMoXB0WJ/d5AE4ktVqEzt4kn
        +mSwojbmgVyQyndefYcQXLHXrFtMJN4TaYJ34Vz78Uo6buSNtXnaZ3DMCNZk3l/U
        c9Op3/hpBJ+YQorwjZG4d/7rGY8JEShDUpHKJ8J6kaZ3HrhUUqOU+ywCPdtrHPNY
        JdC33Zz3fs7HAs0FENj+zWKNTHZ/YJ3r59BB33IsWGw/CKOCKJxrUkiHyUXQkmMl
        +MxNjlFdGhcsJpp6gikZactv6GSfQr6vBOg0139sniu3WdwPO9mBRq32YrJEq4PI
        7H75a2wuZ/2lTHi1AhNPqX2fEpfEKaoefexezkEsSEqPkTUjU+rv2fzJdtqhVIxT
        jI4d7zVcNcmrLIsvvtjKwbWS3yiQN2nfBKgsiII+ii4eFbKrQczXDl/2XFt2MzAe
        zNK2jfkAJmlqx4xu2VYDTdSmcxqz3XETw7Egn2n9YwGX6beVuOqzH299BrbRN7Jp
        vZ+MtMXi44i9IHzqNWljSjJzLYauRljIGRVj3soKjz8u1NjWH+pyJGODxdNH7AYO
        lPICvQiWgNwHNn2xhMxKnf+Ob83/kQIDAQABoAAwDQYJKoZIhvcNAQELBQADggIB
        ALJnAkdcyyyvOGYtpPwPD31J7KvWkY+vX2U0xggL3u4OH40MFsx7/GJM2CKRo5y9
        qP1UvVqXONSqATPjl4r/wnfWR8GSWCMwQhg+ibzl3YQBdSaPbOdwEnunRCIMlDdE
        p/midHiyZLYBUtzoz7d4VmoCJacA9JidXV53xhB2U97M6rzZpnh6/eUEtjGQQQuT
        uCSUjjsl1bVTz4bXOn2PJxCEb2MPYMto7WLkf5JxdwBnROo+BgE4jw62E1MFXg6c
        8KiJXS6jk1k7vNgHZcNjXLYIC0RRDexizZRe7I3Z85edTgrz8rv/KBW8EFuMjnlX
        5c/M6NVdtyCHN+ShuZgi083KH3h5tkoM60MvFW9s+v3IHCTRIPxMZvqEQvasVYS0
        uVo9AZiINYT2MlzO/vvPrDkVmvMrjecgShcSXhe6PelviH8wVDAHCNdwGbbIjQOx
        DPCxk5CZYoLEhixau8b+rPpCjpFZSDuNw6+n8ojXrhBv5KT6M/9xA8zI76jJ+7h9
        cU9auWWdOaYysOohyPh6trW/JH+nbZCQGrsIIe/reaSOd7zUCj631lzQVtpLo4ik
        mHeeIAR7jlZOJuPu9MdUebxWFtxHDOpc7r6IV2RgfBFdm6uBDp/UHRtgULKkSIZA
        kCrYeSLr942w6B2PSDPhQmPeliSQV4QnJT+0J1Q7fCdH
        -----END CERTIFICATE REQUEST-----"""
        inputs['sn_uid'] = sn_uid
        inputs['sn_e'] = 'example@redhat.com'
        inputs['sn_cn'] = 'MyTestUser'

        logger.debug("Client %s: Submitting enrollment request", id)
        enrollment_results = cert_client.enroll_cert('caUserCert', inputs)

        if enrollment_results.__len__() == 0:
            raise Exception("Enrollment results is empty")

        for enrollment_result in enrollment_results:
            request_data = enrollment_result.request
            cert_data = enrollment_result.cert
            if request_data.request_status != 'complete':
                raise Exception("Cert enrollment failed : {}".format(cert_data))
            else:
                self.cert_serial_number = cert_data.serial_number
                logger.debug("Client %s: Certificate: %s", id, cert_data)


class TestClient(threading.Thread):

    def __init__(self, id, connection, number_of_tests_per_client):
        super().__init__()
        self.id= id
        self.connection = connection
        self.number_of_tests_per_client = number_of_tests_per_client
        self.cert_client = CertClient(self.connection)
        return

    def run(self):
        #logging.debug('running with %s and %s', self.args, self.kwargs)
        sn_uid = "testuser{}".format(id)
        # execute the specified number of tests sequentially
        for i in range(1, self.number_of_tests_per_client + 1):
            try:
                logger.info("Client %s: Enrolling cert %s of %s", self.id, i,
                            self.number_of_tests_per_client)
                start = timer()
                serial_num = cert_enroll(id, sn_uid, self.cert_client)
                end = timer()
                issuance_times.append(end - start)
                cert_list.append(serial_num.cert_serial_number)
            except Exception as error:
                logger.error(error)
        return


if __name__ == "__main__":

    if args.debug:
        logger.setLevel(logging.DEBUG)

    elif args.verbose:
        logger.setLevel(logging.INFO)

    print("Test parameters:")
    print("- target: https://%s:%s" % (args.hostname, args.port))

    number_of_clients = args.number_of_clients
    print("- number of clients: %s" % number_of_clients)

    number_of_tests_per_client = args.number_of_tests_per_client
    print("- number of tests per client: %s" % number_of_tests_per_client)

    # Create the specified number of threads
    cert_list = []
    issuance_times = []

    clients = []
    for i in range(number_of_clients):
        id = i + 1
        # Create a PKIConnection object that stores the details of the CA.
        connection = PKIConnection('https', args.hostname, args.port, cert_paths=args.ca_cert_path)

        # The pem file used for authentication. Created from a p12 file using the
        # command -
        # openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes
        connection.set_authentication_cert(args.client_cert)
        client = TestClient( id, connection, number_of_tests_per_client)
        clients.append(client)

    start = timer()

    for client in clients:
        client.start()

    # wait for all threads to complete
    for client in clients:
        client.join()

    end = timer()

    with open("cert_file.txt", "w+") as cf:
        json.dump(cert_list, cf)

    with open("issuance_times.json", "w") as cf:
        json.dump(issuance_times, cf)

    # Below part is for reporting purpose to calculate Throughput
    T = end - start
    N = number_of_clients * number_of_tests_per_client

    print("Number of certs enrolled (N): {}".format(N))
    print("Minimum execution time (T): {}".format(min(issuance_times)))
    print("Maximum execution time (T): {}".format(max(issuance_times)))
    print("Average execution time (T): {}".format(sum(issuance_times)/len(issuance_times)))
    print("Test execution time (T): {}".format(T))
    print("Throughput (V = N/T): {}".format(N / T))
