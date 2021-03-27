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

# Create a PKIConnection object that stores the details of the CA.
connection = PKIConnection('https', args.hostname, args.port, cert_paths=args.ca_cert_path)

# The pem file used for authentication. Created from a p12 file using the
# command -
# openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes
connection.set_authentication_cert(args.client_cert)

# Instantiate the CertClient
cert_client = CertClient(connection)


class cert_enroll(object):
    """
    #This class will enroll the certificate.
    """

    def __init__(self, id, sn_uid):
        """
        Constructor
        """
        # Enrolling an user certificate

        inputs = dict()
        inputs['cert_request_type'] = 'pkcs10'
        inputs['cert_request'] = """-----BEGIN CERTIFICATE REQUEST-----
        MIIBmDCCAQECAQAwWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMRAwDgYDVQQH
        DAdSYWxlaWdoMRUwEwYDVQQKDAxSZWQgSGF0IEluYy4xEzARBgNVBAMMClRlc3RT
        ZXJ2ZXIwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMJpWz92dSYCvWxllrQC
        Y5atPKCswUwyppRNGPnKmJ77AdHBBI4dFyET+h/+69jQMTLZMa8FX7SbyHvgbgLB
        P4Q/RzCSE2S87qFNjriOqiQCqJmcrzDzdncJQiP+O7T6MSpLo3smLP7dK1Vd7vK0
        Vy8yHwV0eBx7DgYedv2slBPHAgMBAAGgADANBgkqhkiG9w0BAQUFAAOBgQBvkxAG
        KwkfK3TKwLc5Mg0IWp8zGRVwxdIlghAL8DugNocCNNgmZazglJOOehLuk0/NkLX1
        ZM5RrVgM09W6kcfWZtIwr5Uje2K/+6tW2ZTGrbizs7CNOTMzA/9H8CkHb4H9P/qR
        T275zHIocYj4smUnXLwWGsBMeGs+OMMbGvSrHg==
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


def run_test(id, number_of_tests_per_thread):
    sn_uid = "testuser{}".format(id)
    # execute the specified number of tests sequentially
    for i in range(1, number_of_tests_per_thread + 1):
        try:
            logger.info("Client %s: Enrolling cert %s of %s", id, i, number_of_tests_per_thread)
            start = timer()
            serial_num = cert_enroll(id, sn_uid)
            end = timer()
            issuance_times.append(end - start)
            cert_list.append(serial_num.cert_serial_number)
        except Exception as error:
            logger.error(error)
    # call cert_enroll(sn_uid)


if __name__ == "__main__":

    if args.debug:
        logger.setLevel(logging.DEBUG)

    elif args.verbose:
        logger.setLevel(logging.INFO)

    print("Test parameters:")
    print("- target: https://%s:%s" % (args.hostname, args.port))

    number_of_threads = args.number_of_clients
    print("- number of clients: %s" % number_of_threads)

    number_of_tests_per_thread = args.number_of_tests_per_client
    print("- number of tests per client: %s" % number_of_tests_per_thread)

    # create the specified number of threads
    threads = []
    cert_list = []
    issuance_times = []
    start = timer()

    for t in range(1, number_of_threads + 1):
        logger.info("Starting client %s" % t)
        t1 = threading.Thread(target=run_test, args=(t, number_of_tests_per_thread))
        t1.start()
        threads.append(t1)

    # wait for all threads to complete
    for t in threads:
        t.join()
    end = timer()

    with open("cert_file.txt", "w+") as cf:
        json.dump(cert_list, cf)

    with open("issuance_times.json", "w") as cf:
        json.dump(issuance_times, cf)

    # Below part is for reporting purpose to calculate Throughput
    T = end - start
    N = number_of_threads * number_of_tests_per_thread

    print("Number of certs enrolled (N): {}".format(N))
    print("Minimum execution time (T): {}".format(min(issuance_times)))
    print("Maximum execution time (T): {}".format(max(issuance_times)))
    print("Average execution time (T): {}".format(sum(issuance_times)/len(issuance_times)))
    print("Test execution time (T): {}".format(T))
    print("Throughput (V = N/T): {}".format(N / T))
