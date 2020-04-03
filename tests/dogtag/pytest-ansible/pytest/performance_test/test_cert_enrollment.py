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
import os
import sys
import threading
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--url", help="<CA hostname>")
parser.add_argument("--port", help="<CA Port Number>")
parser.add_argument("--client-cert", help="path for admin.pem certificate")
parser.add_argument("--number-of-threads", help="Number of thread", type=int)
parser.add_argument("--number-of-tests-per-thread", help="Number of test per thread", type=int)

args = parser.parse_args()

# Create a PKIConnection object that stores the details of the CA.
connection = PKIConnection('https', args.url,args.port,'ca')

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

    def __init__(self, sn_uid):
        """
        Constructor
        """
        # Enrolling an user certificate
        print('Enrolling an user certificate')
        print('-----------------------------')

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

        enrollment_results = cert_client.enroll_cert('caUserCert', inputs)

        for enrollment_result in enrollment_results:
            request_data = enrollment_result.request
            cert_data = enrollment_result.cert
            print('Request ID: ' + request_data.request_id)

def run_test(sn_uid, number_of_tests_per_thread):
    # execute the specified number of tests sequentially
    for i in range(number_of_tests_per_thread):
        cert_enroll(sn_uid)
    # call cert_enroll(sn_uid)


if __name__ == "__main__":
    # get test parameters from CLI parameters
    number_of_threads = args.number_of_threads
    number_of_tests_per_thread = args.number_of_tests_per_thread

    # create the specified number of threads
    threads = []

    for t in range(number_of_threads):
        t1 = threading.Thread(target=run_test, args=("testuser{}".format(t), number_of_tests_per_thread))
        t1.start()
    threads.append(t1)

# wait for all threads to complete
# (not sure if this is needed since Python probably won’t exit until all threads are complete)
for t in threads:
    t.join()

