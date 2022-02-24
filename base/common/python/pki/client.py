# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the Lesser GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2013 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function

import functools
import inspect
import logging
import os
import ssl
import warnings

import requests
from requests import adapters
from requests.adapters import DEFAULT_POOLBLOCK, DEFAULT_POOLSIZE, DEFAULT_RETRIES
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except ImportError:
    from urllib3.exceptions import InsecureRequestWarning

logger = logging.getLogger(__name__)


def catch_insecure_warning(func):
    """Temporary silence InsecureRequestWarning

    PKIConnection is not able to verify HTTPS connections yet. This decorator
    catches the warning.

    :see: https://fedorahosted.org/pki/ticket/1253
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', InsecureRequestWarning)
            return func(self, *args, **kwargs)
    return wrapper


class SSLContextAdapter(adapters.HTTPAdapter):
    """
    Custom SSLContext Adapter for requests
    """

    def __init__(self, pool_connections=DEFAULT_POOLSIZE,
                 pool_maxsize=DEFAULT_POOLSIZE, max_retries=DEFAULT_RETRIES,
                 pool_block=DEFAULT_POOLBLOCK, verify=True,
                 cert_paths=None):
        self.verify = verify
        self.cafiles = []
        self.capaths = []

        cert_paths = cert_paths or []

        if isinstance(cert_paths, str):
            cert_paths = [cert_paths]

        for path in cert_paths:
            path = path and os.path.expanduser(path)

            if os.path.isdir(path):
                self.capaths.append(path)
            elif os.path.exists(path):
                self.cafiles.append(path)
            else:
                logger.warning("cert_path missing; not used for validation: %s",
                               path)

        # adapters.HTTPAdapter.__init__ calls our init_poolmanager, which needs
        # our cafiles/capaths variables we set up above.
        super(SSLContextAdapter, self).__init__(pool_connections=pool_connections,
                                                pool_maxsize=pool_maxsize,
                                                max_retries=max_retries,
                                                pool_block=pool_block)

    def init_poolmanager(self, connections, maxsize,
                         block=adapters.DEFAULT_POOLBLOCK, **pool_kwargs):
        context = ssl.SSLContext(
            ssl.PROTOCOL_TLS  # pylint: disable=no-member
        )

        # Enable post handshake authentication for TLS 1.3
        if getattr(context, "post_handshake_auth", None) is not None:
            context.post_handshake_auth = True

        # Load from the system trust store when possible; per documentation
        # this call could silently fail and refuse to configure any
        # certificates. In this instance, the user should provide a
        # certificate manually.
        context.set_default_verify_paths()

        # Load any specific certificate paths that have been specified during
        # adapter initialization.
        for cafile in self.cafiles:
            context.load_verify_locations(cafile=cafile)
        for capath in self.capaths:
            context.load_verify_locations(capath=capath)

        if self.verify:
            # Enable certificate verification
            context.verify_mode = ssl.VerifyMode.CERT_REQUIRED  # pylint: disable=no-member

        pool_kwargs['ssl_context'] = context
        return super().init_poolmanager(
            connections, maxsize, block, **pool_kwargs
        )


class PKIConnection:
    """
    Class to encapsulate the connection between the client and a Dogtag
    subsystem.
    """

    def __init__(self, protocol='http', hostname='localhost', port='8080',
                 subsystem=None, accept='application/json',
                 trust_env=None, verify=True, cert_paths=None):
        """
        Set the parameters for a python-requests based connection to a
        Dogtag subsystem.
        :param protocol: http or https
        :type protocol: str
        :param hostname: hostname of server
        :type hostname: str
        :param port: port of server
        :type port: str
        :param subsystem: Subsystem name: ca, kra, ocsp, tks, tps.
           DEPRECATED: https://www.dogtagpki.org/wiki/PKI_10.8_Python_Changes
        :type subsystem: str
        :param accept: value of accept header.  Supported values are usually
           'application/json' or 'application/xml'
        :type accept: str
        :param trust_env: use environment variables for http proxy and other
           requests settings (default: yes)
        :type trust_env: bool, None
        :param verify: verify TLS/SSL connections and configure CA certs
           (default: no)
        :type verify: None, bool, str
        :param cert_paths: paths to CA certificates / directories in OpenSSL
          format. (default: None)
        :type cert_paths: None, str, list
        :return: PKIConnection object.
        """

        self.protocol = protocol
        self.hostname = hostname
        self.port = port
        self.subsystem = subsystem

        self.rootURI = self.protocol + '://' + self.hostname

        if self.port is not None:
            self.rootURI = self.rootURI + ':' + self.port

        if subsystem is not None:
            logger.warning(
                '%s:%s: The subsystem in PKIConnection.__init__() has been deprecated '
                '(https://www.dogtagpki.org/wiki/PKI_10.8_Python_Changes).',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)
            self.serverURI = self.rootURI + '/' + subsystem
        else:
            self.serverURI = self.rootURI

        self.session = requests.Session()
        self.session.mount("https://", SSLContextAdapter(verify=verify, cert_paths=cert_paths))
        self.session.trust_env = trust_env
        self.session.verify = verify

        if accept:
            self.session.headers.update({'Accept': accept})

    def authenticate(self, username=None, password=None):
        """
        Set the parameters used for authentication if username/password is to
        be used.  Both username and password must not be None.
        Note that this method only sets the parameters.  Actual authentication
        occurs when the connection is attempted,

        :param username: username to authenticate connection
        :param password: password to authenticate connection
        :return: None
        """
        if username is not None and password is not None:
            self.session.auth = (username, password)

    def set_authentication_cert(self, pem_cert_path, pem_key_path=None):
        """
        Set the path to the PEM file containing the certificate and private key
        for the client certificate to be used for authentication to the server,
        when client certificate authentication is required. The private key may
        optionally be stored in a different path.

        :param pem_cert_path: path to the PEM file
        :type pem_cert_path: str
        :param pem_key_path: path to the PEM-formatted private key file
        :type pem_key_path: str
        :return: None
        :raises: Exception if path is empty or None.
        """
        if pem_cert_path is None:
            raise Exception("No path for the certificate specified.")
        if len(str(pem_cert_path)) == 0:
            raise Exception("No path for the certificate specified.")
        if pem_key_path is not None:
            self.session.cert = (pem_cert_path, pem_key_path)
        else:
            self.session.cert = pem_cert_path

    @catch_insecure_warning
    def get(self, path, headers=None, params=None, payload=None,
            use_root_uri=False, timeout=None):
        """
        Uses python-requests to issue a GET request to the server.

        :param path: path URI for the GET request
        :type path: str
        :param headers: headers for the GET request
        :type headers: dict
        :param params: Query parameters for the GET request
        :type params: dict or bytes
        :param payload: data to be sent in the body of the request
        :type payload: dict, bytes, file-like object
        :param use_root_uri: use root URI instead of subsystem URI as base
        :type use_root_uri: boolean
        :returns: request.response -- response from the server
        :raises: Exception from python-requests in case the GET was not
            successful, or returns an error code.
        """
        if use_root_uri:
            logger.warning(
                '%s:%s: The use_root_uri in PKIConnection.get() has been deprecated '
                '(https://www.dogtagpki.org/wiki/PKI_10.8_Python_Changes).',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)
            target_path = self.rootURI + path
        else:
            target_path = self.serverURI + path

        r = self.session.get(
            target_path,
            headers=headers,
            params=params,
            data=payload,
            timeout=timeout,
        )
        r.raise_for_status()
        return r

    @catch_insecure_warning
    def post(self, path, payload, headers=None, params=None,
             use_root_uri=False):
        """
        Uses python-requests to issue a POST request to the server.

        :param path: path URI for the POST request
        :type path: str
        :param payload: data to be sent in the body of the request
        :type payload: dict, bytes, file-like object
        :param headers: headers for the POST request
        :type headers: dict
        :param params: Query parameters for the POST request
        :type params: dict or bytes
        :param use_root_uri: use root URI instead of subsystem URI as base
        :type use_root_uri: boolean
        :returns: request.response -- response from the server
        :raises: Exception from python-requests in case the POST was not
            successful, or returns an error code.
        """
        if use_root_uri:
            logger.warning(
                '%s:%s: The use_root_uri in PKIConnection.post() has been deprecated '
                '(https://www.dogtagpki.org/wiki/PKI_10.8_Python_Changes).',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)
            target_path = self.rootURI + path
        else:
            target_path = self.serverURI + path

        r = self.session.post(
            target_path,
            data=payload,
            headers=headers,
            params=params)
        r.raise_for_status()
        return r

    @catch_insecure_warning
    def put(self, path, payload, headers=None, use_root_uri=False):
        """
        Uses python-requests to issue a PUT request to the server.

        :param path: path URI for the PUT request
        :type path: str
        :param payload: data to be sent in the body of the request
        :type payload: dict, bytes, file-like object
        :param headers: headers for the PUT request
        :type headers: dict
        :param use_root_uri: use root URI instead of subsystem URI as base
        :type use_root_uri: boolean
        :returns: request.response -- response from the server
        :raises: Exception from python-requests in case the PUT was not
            successful, or returns an error code.
        """
        if use_root_uri:
            logger.warning(
                '%s:%s: The use_root_uri in PKIConnection.put() has been deprecated '
                '(https://www.dogtagpki.org/wiki/PKI_10.8_Python_Changes).',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)
            target_path = self.rootURI + path
        else:
            target_path = self.serverURI + path

        r = self.session.put(target_path, payload, headers=headers)
        r.raise_for_status()
        return r

    @catch_insecure_warning
    def delete(self, path, headers=None, use_root_uri=False):
        """
        Uses python-requests to issue a DEL request to the server.

        :param path: path URI for the DEL request
        :type path: str
        :param headers: headers for the DEL request
        :type headers: dict
        :param use_root_uri: use root URI instead of subsystem URI as base
        :type use_root_uri: boolean
        :returns: request.response -- response from the server
        :raises: Exception from python-requests in case the DEL was not
            successful, or returns an error code.
        """
        if use_root_uri:
            logger.warning(
                '%s:%s: The use_root_uri in PKIConnection.delete() has been deprecated '
                '(https://www.dogtagpki.org/wiki/PKI_10.8_Python_Changes).',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)
            target_path = self.rootURI + path
        else:
            target_path = self.serverURI + path

        r = self.session.delete(target_path, headers=headers)
        r.raise_for_status()
        return r


def main():
    """
    Test code for the PKIConnection class.
    :return: None
    """
    conn = PKIConnection()
    headers = {'Content-type': 'application/json',
               'Accept': 'application/json'}
    conn.set_authentication_cert('/root/temp4.pem')
    print(conn.get("", headers).json())


if __name__ == "__main__":
    main()
