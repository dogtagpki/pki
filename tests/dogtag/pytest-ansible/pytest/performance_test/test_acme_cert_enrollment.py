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

import argparse
import subprocess
import json
import os, sys
import base64
import binascii, time
import hashlib
import re, logging
import socket
import threading
import OpenSSL
from acme import crypto_util
from timeit import default_timer as timer
from urllib.request import urlopen, Request

DEFAULT_CHALLENGE_DIR = "/usr/share/nginx/html/.well-known/acme-challenge"
DEFAULT_DIRECTORY_URL = "http://%s:8080/acme/directory" % socket.gethostname()

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(levelname)s: %(message)s')

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--domain",
                    help="Client domain name (default: localhost)",
                    default="localhost")
parser.add_argument("--acme-dir",
                    help="Path to .well-known/acme-challenge directory (default: %s)" % DEFAULT_CHALLENGE_DIR,
                    default=DEFAULT_CHALLENGE_DIR)
parser.add_argument("--directory-url",
                    help="ACME directory URL (default: %s)" % DEFAULT_DIRECTORY_URL,
                    default=DEFAULT_DIRECTORY_URL)
parser.add_argument("--number-of-threads", "--clients",
                    help="Number of clients (default: 1)",
                    default=1,
                    type=int)
parser.add_argument("--number-of-tests-per-thread", "--tests-per-client",
                    help="Number of tests per client (default: 1)",
                    default=1,
                    type=int)
parser.add_argument("-v", "--verbose",
                    help="Run in verbose mode.",
                    action="store_true")
parser.add_argument("--debug",
                    help="Run in debug mode.",
                    action="store_true")

args = parser.parse_args()

account_key = "{}.key".format(args.domain)
csr = "{}.csr".format(args.domain)


def new_csr_comp(domain_name, pkey_pem=None):
    """Create certificate signing request."""
    if pkey_pem is None:
        # Create private key.
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        pkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)
        kf = open(account_key, "wb")
        kf.write(pkey_pem)
        kf.close()
    csr_pem = crypto_util.make_csr(pkey_pem, [domain_name])
    cf = open(csr, "wb")
    cf.write(csr_pem)
    cf.close()
    return pkey_pem, csr_pem, pkey


# helper functions - base64 encode for jose spec
def b64(b):
    return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")


# helper function - make request and automatically parse json response
def do_request(url, data=None, err_msg="Error"):
    resp = urlopen(
        Request(url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "acme-cert"}))
    resp_data, code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
    nonce = headers['Replay-Nonce']

    try:
        resp_data = json.loads(resp_data)  # try to parse json results
    except ValueError:
        pass  # ignore json parsing errors
    return resp_data, code, headers, nonce


# helper function - make signed requests
def send_signed_request(url, payload, err_msg, acct_headers=None, nonce=None):
    payload64 = "" if payload is None else b64(json.dumps(payload).encode('utf8'))
    protected = {"url": url, "alg": "RS256", "nonce": nonce}
    protected.update({"jwk": jwk} if acct_headers is None else {"kid": acct_headers['Location']})
    protected64 = b64(json.dumps(protected).encode('utf8'))
    protected_input = "{0}.{1}".format(protected64, payload64).encode('utf8')
    out = OpenSSL.crypto.sign(pkey, protected_input, "sha256")
    data = json.dumps({"protected": protected64, "payload": payload64, "signature": b64(out)})
    return do_request(url, data=data.encode('utf8'), err_msg=err_msg)


# helper function - poll until complete
def poll_until_not(url, statuses, err_msg, acct_headers=None, nonce=None):
    result, t0 = None, time.time()
    while result is None or result['status'] in statuses:
        assert (time.time() - t0 < 3600), "Polling timeout"  # 1 hour timeout
        time.sleep(0 if result is None else 2)
        result, _, _, nonce = send_signed_request(url, None, err_msg, acct_headers=acct_headers,
                                                  nonce=nonce)
    return result, nonce


def get_crt(id, domain_name, acme_dir, nonce=None):
    # create a new order
    order_payload = {"identifiers": [{"type": "dns", "value": d} for d in {domain_name}]}
    order, _, order_headers, nonce = send_signed_request(directory['newOrder'], order_payload,
                                                         "Error creating new order", acct_headers=acct_headers,
                                                         nonce=nonce)
    logger.debug("Client %s: Order: %s", id, order)

    # get the authorizations that need to be completed
    wellknown_paths = []
    for auth_url in order['authorizations']:

        logger.debug("Client %s: Retrieving authorization from %s", id, auth_url)
        authorization, _, _, nonce = send_signed_request(auth_url, None, "Error getting challenges",
                                                         acct_headers=acct_headers, nonce=nonce)
        logger.debug("Client %s: Authorization: %s", id, authorization)

        domain = authorization['identifier']['value']

        # find the http-01 challenge and write the challenge file
        challenge = [c for c in authorization['challenges'] if c['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, thumbprint)

        wellknown_path = os.path.join(acme_dir, token)
        logger.debug("Client %s: Creating challenge response at %s", id, wellknown_path)

        wellknown_paths.append(wellknown_path)
        with open(wellknown_path, "w") as wellknown_file:
            wellknown_file.write(keyauthorization)

        logger.debug("Client %s: Responding to challenge at %s", id, challenge['url'])
        authorization, _, _, nonce = send_signed_request(challenge['url'], {},
                                                         "Error submitting challenges: {0}".format(domain),
                                                         acct_headers=acct_headers, nonce=nonce)

    logger.debug("Client %s: Waiting for all authorizations to complete", id)
    order, nonce = poll_until_not(order_headers['Location'], ['pending'],
                                  "Error checking challenge status for {0}".format(domain),
                                  acct_headers=acct_headers, nonce=nonce)
    if order['status'] != 'ready':
        raise ValueError("Order failed: {0}".format(order))

    for wellknown_path in wellknown_paths:
        os.remove(wellknown_path)

    logger.debug("Client %s: Finalizing order", id)
    authorization, _, _, nonce = send_signed_request(order['finalize'], {"csr": b64(csr_der)},
                                                     "Error finalizing order",
                                                     acct_headers=acct_headers, nonce=nonce)

    logger.debug("Client %s: Waiting for certificate to be issued", id)
    order, nonce = poll_until_not(order_headers['Location'], ["processing"],
                                  "Error checking order status", acct_headers=acct_headers, nonce=nonce)
    if order['status'] != "valid":
        raise ValueError("Order failed: {0}".format(order))

    # download the certificate
    certificate_pem, _, _, nonce = send_signed_request(order['certificate'], None,
                                                       "Certificate download failed",
                                                       acct_headers=acct_headers, nonce=nonce)

    logger.debug("Client %s: Certificate: %s", id, certificate_pem)
    return nonce


def main(id, domain_name, number_of_tests_per_thread):

    logger.debug("Client %s: Getting a new nonce", id)
    nonce = do_request(directory['newNonce'])[2]['Replay-Nonce']
    logger.debug("Client %s: Nonce: %s", id, nonce)

    for i in range(1, number_of_tests_per_thread + 1):
        logger.info("Client %s: Enrolling cert %s of %s", id, i, number_of_tests_per_thread)
        nonce = get_crt(id, domain_name, args.acme_dir, nonce=nonce)


if __name__ == "__main__":  # pragma: no cover

    if args.debug:
        logger.setLevel(logging.DEBUG)

    elif args.verbose:
        logger.setLevel(logging.INFO)

    print("Test parameters:")
    print("- target: %s" % args.directory_url)

    number_of_threads = args.number_of_threads
    print("- number of clients: %s" % number_of_threads)

    number_of_tests_per_thread = args.number_of_tests_per_thread
    print("- number of tests per client: %s" % number_of_tests_per_thread)

    logger.debug("Getting ACME directory from %s", args.directory_url)

    directory, _, _, nonce = do_request(args.directory_url, err_msg="Error getting directory")
    logger.debug("Directory: %s", directory)

    logger.debug("Generating a new CSR")
    pkey_pem, csr_pem, pkey = new_csr_comp(args.domain)
    logger.debug("CSR: %s", csr_pem)

    # parse account key to get public key
    proc = subprocess.Popen(["openssl", "rsa", "-in", account_key, "-noout", "-text"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError(err)
    pub_pattern = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    pub_hex, pub_exp = re.search(pub_pattern, out.decode('utf8'), re.MULTILINE | re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp

    jwk = {
        "e": b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
        "kty": "RSA",
        "n": b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8")))
    }
    logger.debug("JWK: %s", jwk)

    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    thumbprint = b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    logger.debug("Getting a new nonce")
    nonce = do_request(directory['newNonce'])[2]['Replay-Nonce']
    logger.debug("Nonce: %s", nonce)

    logger.debug("Creating a new account")
    reg_payload = {"termsOfServiceAgreed": True}
    account, code, acct_headers, nonce = send_signed_request(directory['newAccount'], reg_payload,
                                                             "Error registering", nonce=nonce)
    logger.debug("Account: %s", account)

    # Convert csr to der
    csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_pem)
    csr_der = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_ASN1, csr)

    # start performance test
    threads = []
    start = timer()
    for t in range(1, number_of_threads + 1):
        logger.info("Starting client %s", t)
        t1 = threading.Thread(target=main, args=(t, args.domain, number_of_tests_per_thread))
        t1.start()
        threads.append(t1)

    # wait for all threads to complete
    for t in threads:
        t.join()
    end = timer()

    # Below part is for reporting purpose to calculate Throughput
    T = end - start
    N = number_of_threads * number_of_tests_per_thread

    print("Number of certs enrolled (N): {}".format(N))
    print("Test execution time (T): {}".format(T))
    print("Throughput (V = N/T): {}".format(N / T))
