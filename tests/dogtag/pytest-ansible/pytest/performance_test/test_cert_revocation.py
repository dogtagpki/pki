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


class TestClient(threading.Thread):

    def __init__(self, connection, cert_sn, number_of_tests_per_client):
        super().__init__()
        self.connection = connection
        self.number_of_tests_per_client = number_of_tests_per_client
        self.cert_sn = cert_sn
        self.cert_client = CertClient(self.connection)
        return

    def run(self):
        # execute the specified number of tests
        for sn in range(self.number_of_tests_per_client):
            try:
                start = timer()
                log.info("Revoking Cert : {}".format(self.cert_sn[sn]))
                revoke_data = self.cert_client.revoke_cert(self.cert_sn[sn], revocation_reason='Key_Compromise')
                end = timer()
                revocation_times.append(end - start)
            except Exception as error:
                log.error(error)
        return


if __name__ == "__main__":
    # get test parameters from CLI parameters
    number_of_clients = args.number_of_clients
    number_of_tests_per_client = args.number_of_tests_per_client
    # execute the test_cert_enrollement.py script and store Serial Number data into file
    # provide that file path to this script by using --cert_sn_file <file path>
    cert_sn_file = open(args.cert_sn_file, 'r')
    cert_list = json.load(cert_sn_file)

    # Dividing the list into small sublist
    sub_list = lambda cert_list, n: [cert_list[x: x + n] for x in range(0, len(cert_list), n)]
    sub_list = sub_list(cert_list, number_of_tests_per_client)

    revocation_times = []
    clients = []

    for nth in range(number_of_clients):
        # Create a PKIConnection object that stores the details of the CA.
        connection = PKIConnection('https', args.hostname, args.port, cert_paths=args.ca_cert_path)

        # The pem file used for authentication. Created from a p12 file using the
        # command -
        # openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes
        connection.set_authentication_cert(args.client_cert)
        client = TestClient( connection, sub_list[nth], number_of_tests_per_client)
        clients.append(client)

    start = timer()
    for client in clients:
        client.start()

    # wait for all threads to complete
    for client in clients:
        client.join()

    end = timer()
    with open("revocation_times.json", "w") as cf:
        json.dump(revocation_times, cf)

    T = end - start
    N = number_of_clients * number_of_tests_per_client

    log.info("Number of certs Revoked (N)={}".format(N))
    log.info("Minimum execution time (T)={}".format(min(revocation_times)))
    log.info("Maximum execution time (T)={}".format(max(revocation_times)))
    log.info("Average execution time (T)={}".format(sum(revocation_times)/len(revocation_times)))
    log.info("Test execution time (T)={}".format(T))
    log.info("Throughput (V = N/T)={}".format(N / T))
