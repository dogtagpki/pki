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
import threading
import argparse
from pki.client import PKIConnection
from pki.cert import CertClient
from timeit import default_timer as timer
import sys
import logging
import json

parser = argparse.ArgumentParser()
parser.add_argument("--hostname", help="<CA hostname>")
parser.add_argument("--port", help="<CA Port Number>")
parser.add_argument("--client-cert", help="path for admin.pem certificate")
parser.add_argument("--number-of-clients", help="Number of thread", type=int)
parser.add_argument("--number-of-tests-per-client", help="Number of test per thread", type=int)
parser.add_argument("--cert_sn_file", help="path for certificate serial number file")
parser.add_argument("--ca-cert-path", help="path for CA signing certifcate")

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

args = parser.parse_args()

# Create a PKIConnection object that stores the details of the CA.
connection = PKIConnection('https', args.hostname, args.port, cert_paths=args.ca_cert_path)

# The pem file used for authentication. Created from a p12 file using the
# command -
# openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes
connection.set_authentication_cert(args.client_cert)

# Instantiate the CertClient
cert_client = CertClient(connection)


def run_test(cert_sn, number_of_tests_per_thread):
    # execute the specified number of tests
    for sn in range(number_of_tests_per_thread):
        start = timer()
        revoke_data = cert_client.revoke_cert(cert_sn[sn], revocation_reason='Key_Compromise')
        end = timer()
        revocation_times.append(int(end - start))
        if revoke_data.operation_result != 'success':
            raise Exception("Cert enrollment failed : {}".format(revoke_data.request_id))


if __name__ == "__main__":
    # get test parameters from CLI parameters
    number_of_threads = args.number_of_clients
    number_of_tests_per_thread = args.number_of_tests_per_client
    # execute the test_cert_enrollement.py script and store Serial Number data into file
    # provide that file path to this script by using --cert_sn_file <file path>
    cert_sn_file = open(args.cert_sn_file, 'r')
    cert_list = json.load(cert_sn_file)

    # Dividing the list into small sublist
    sub_list = lambda cert_list, n: [cert_list[x: x + n] for x in range(0, len(cert_list), n)]
    sub_list = sub_list(cert_list, number_of_tests_per_thread)

    # create the specified number of threads
    threads = []
    revocation_times = []

    start = timer()
    for nth in range(number_of_threads):
        t1 = threading.Thread(target=run_test, args=(sub_list[nth], number_of_tests_per_thread))
        t1.start()
        threads.append(t1)

    # wait for all threads to complete
    for t in threads:
        t.join()
    end = timer()

    with open("revocation_times.json", "w") as cf:
        json.dump(revocation_times, cf)

    T = int(end - start)
    N = number_of_threads * number_of_tests_per_thread

    log.info("Number of certs Revoked (N)={}".format(N))
    log.info("Minimum execution time (T)={}".format(min(revocation_times)))
    log.info("Maximum execution time (T)={}".format(max(revocation_times)))
    log.info("Average execution time (T)={}".format(sum(revocation_times)/len(revocation_times)))
    log.info("Test execution time (T)={}".format(T))
    log.info("Throughput (V = N/T)={}".format(N / T))
