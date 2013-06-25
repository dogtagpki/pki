# Authors:
#   Ade Lee <alee@redhat.com>
#
# Copyright (C) 2012  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

'''

============================================================
Python Test client for KRA using the new RESTful interface
============================================================

This is a python client that can be used to retrieve key requests
and keys from a KRA using the new RESTful interface.  Moreover, given
a PKIArchiveOptions structure containing either a passphrase or a symmetric
key, this data can be stored in and retrieved from the KRA.

A sample test execution is provided at the end of the file.
'''

from lxml import etree
import nss.nss as nss
import httplib
from ipapython import nsslib, ipautil
from nss.error import NSPRError
from ipalib.errors import NetworkError, CertificateOperationError
from urllib import urlencode, quote_plus
from datetime import datetime
import logging
import base64

CERT_HEADER = "-----BEGIN NEW CERTIFICATE REQUEST-----"
CERT_FOOTER = "-----END NEW CERTIFICATE REQUEST-----"

def _(string):
    return string

def parse_key_request_info_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict
    :except ValueError:

    After parsing the results are returned in a result dict. The following
    table illustrates the mapping from the CMS data item to what may be found in
    the result dict. If a CMS data item is absent it will also be absent in the
    result dict.

    +----------------------+----------------+-----------------------+---------------+
    |cms name              |cms type        |result name            |result type    |
    +======================+================+=======================+===============+
    |requestType           |string          |request_type           |string         |
    +----------------------+----------------+-----------------------+---------------+
    |requestStatus         |string          |request_status         |string         |
    +----------------------+----------------+-----------------------+---------------+
    |requestURL            |string          |request_id             |string         |
    +----------------------+----------------+-----------------------+---------------+
    |keyURL                |string          |key_id                 |string         |
    +----------------------+----------------+-----------------------+---------------+
    '''
    response = {}

    request_type = doc.xpath('requestType')
    if len(request_type) == 1:
        request_type = etree.tostring(request_type[0], method='text',
                                           encoding=unicode).strip()
        response['request_type'] = request_type

    request_status = doc.xpath('requestStatus')
    if len(request_status) == 1:
        request_status = etree.tostring(request_status[0], method='text',
                                           encoding=unicode).strip()
        response['request_status'] = request_status

    request_url = doc.xpath('requestURL')
    if len(request_url) == 1:
        request_url = etree.tostring(request_url[0], method='text',
                                           encoding=unicode).strip()
        response['request_id'] = request_url.rsplit('/', 1)[1]

    key_url = doc.xpath('keyURL')
    if len(key_url) == 1:
        key_url = etree.tostring(key_url[0], method='text',
                                           encoding=unicode).strip()
        response['key_id'] = key_url.rsplit('/', 1)[1]

    return response

def parse_key_request_infos_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict
    :except ValueError:

    After parsing the results are returned in a result dict. The following
    table illustrates the mapping from the CMS data item to what may be found in
    the result dict. If a CMS data item is absent it will also be absent in the
    result dict.

    +----------------------+------------------------+-----------------------+---------------+
    |cms name              |cms type                |result name            |result type    |
    +======================+========================+=======================+===============+
    |next                  |Link                    |next_id                |unicode  [1]   |
    +----------------------+------------------------+-----------------------+---------------+
    |prev                  |Link                    |prev_id                |unicode  [1]   |
    +----------------------+------------------------+-----------------------+---------------+
    |info for each request |KeyRequestInfo          |request_id [2]         |dict           |
    +----------------------+------------------------+-----------------------+---------------+

    [1] prev_id and next_id are the starting ids for the previous and next pages
        respectively.  They are extracted from the href elements of the Link
        nodes (if they exist)
    [2] For each key request info returned, we store a dict containing the key request data.
        See parse_key_request_info_xml for details.  Each dict is referenced by the id
        of the key request (extracted from the key request URL).
    '''
    response = {}
    next_link = doc.xpath('//Link[@rel="next"]/href')
    if len(next_link) == 1:
        next_link = etree.tostring(next_link[0], method='text',
                                   encoding=unicode).strip()
        next_link = next_link.rsplit('/', 1)[1]
        response['next_id'] = next_link

    prev_link = doc.xpath('//Link[@rel="previous"]/href')
    if len(prev_link) == 1:
        prev_link = etree.tostring(prev_link[0], method='text',
                                   encoding=unicode).strip()
        prev_link = prev_link.rsplit('/', 1)[1]
        response['prev_id'] = prev_link

    key_request_infos = doc.xpath('//KeyRequestInfo')
    for key_request in key_request_infos:
        node = parse_key_request_info_xml(key_request)
        response[node['request_id']] = node

    return response

def parse_key_data_info_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict
    :except ValueError:

    After parsing the results are returned in a result dict. The following
    table illustrates the mapping from the CMS data item to what may be found in
    the result dict. If a CMS data item is absent it will also be absent in the
    result dict.

    +----------------------+----------------+-----------------------+---------------+
    |cms name              |cms type        |result name            |result type    |
    +======================+================+=======================+===============+
    |clientID              |string          |client_id              |string         |
    +----------------------+----------------+-----------------------+---------------+
    |keyURL                |string          |key_url                |string         |
    +----------------------+----------------+-----------------------+---------------+
    '''
    response = {}

    client_id = doc.xpath('clientID')
    if len(client_id) == 1:
        client_id = etree.tostring(client_id[0], method='text',
                                           encoding=unicode).strip()
        response['client_id'] = client_id

    key_url = doc.xpath('keyURL')
    if len(key_url) == 1:
        key_url = etree.tostring(key_url[0], method='text',
                                           encoding=unicode).strip()
        response['key_url'] = key_url

    return response

def parse_key_data_infos_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict
    :except ValueError:

    After parsing the results are returned in a result dict. The following
    table illustrates the mapping from the CMS data item to what may be found in
    the result dict. If a CMS data item is absent it will also be absent in the
    result dict.

    +----------------------+-----------------+-----------------------+---------------+
    |cms name              |cms type         |result name            |result type    |
    +======================+=================+=======================+===============+
    |next                  |Link             |next_id                |unicode  [1]   |
    +----------------------+-----------------+-----------------------+---------------+
    |prev                  |Link             |prev_id                |unicode  [1]   |
    +----------------------+-----------------+-----------------------+---------------+
    |info for each key     |KeyDataInfo      |key_id [2]             |dict           |
    +----------------------+-----------------+-----------------------+---------------+

    [1] prev_id and next_id are the starting ids for the previous and next pages
        respectively.  They are extracted from the href elements of the Link
        nodes (if they exist)
    [2] For each key info returned, we store a dict containing the key data.
        See parse_key_data_info_xml for details.  Each dict is referenced by the id
        of the key (extracted from the key URL).
    '''
    response = {}

    next_link = doc.xpath('//Link[@rel="next"]/href')
    if len(next_link) == 1:
        next_link = etree.tostring(next_link[0], method='text',
                                   encoding=unicode).strip()
        next_link = next_link.rsplit('/', 1)[1]
        response['next_id'] = next_link

    prev_link = doc.xpath('//Link[@rel="previous"]/href')
    if len(prev_link) == 1:
        prev_link = etree.tostring(prev_link[0], method='text',
                                   encoding=unicode).strip()
        prev_link = prev_link.rsplit('/', 1)[1]
        response['prev_id'] = prev_link

    key_data_infos = doc.xpath('//KeyDataInfo')
    for key_data in key_data_infos:
        node = parse_key_data_info_xml(key_data)
        response[node['key_url'].rsplit('/', 1)[1]] = node

    return response

def parse_key_data_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict
    :except ValueError:

    After parsing the results are returned in a result dict.

    +----------------------+----------------+-----------------------+---------------+
    |cms name			   |cms type		|result name			|result type	|
    +======================+================+=======================+===============+
    |wrappedPrivateData	   |string		    |wrapped_data	  	    |unicode	    |
    +----------------------+----------------+-----------------------+---------------+
    |nonceData             |string          |nonce_data             |unicode        |
    +----------------------+----------------+-----------------------+---------------+

    '''
    response = {}

    wrapped_data = doc.xpath('wrappedPrivateData')
    if len(wrapped_data) == 1:
        wrapped_data = etree.tostring(wrapped_data[0], method='text',
                                      encoding=unicode).strip()
        response['wrapped_data'] = wrapped_data

    nonce_data = doc.xpath('nonceData')
    if len(nonce_data) == 1:
        nonce_data = etree.tostring(nonce_data[0], method='text',
                                    encoding=unicode).strip()
        response['nonce_data'] = nonce_data

    return response

def parse_certificate_data_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict
    :except ValueError:

    After parsing the results are returned in a result dict.

    +----------------------+----------------+-----------------------+---------------+
    |cms name			   |cms type		|result name			|result type	|
    +======================+================+=======================+===============+
    |b64            	   |string	[1]     |cert	        	    |unicode	    |
    +----------------------+----------------+-----------------------+---------------+

    [1] Base-64 encoded certificate with header and footer
    '''
    response = {}

    b64 = doc.xpath('b64')
    if len(b64) == 1:
        b64 = etree.tostring(b64[0], method='text',
                             encoding=unicode).strip()
        response['cert'] = b64.replace(CERT_HEADER, "").replace(CERT_FOOTER, "")

    return response

def https_request(host, port, url, secdir, password, nickname, operation, args, **kw):
    """
    :param url:        The URL to post to.
    :param operation:  GET, POST, (PUT and DELETE not yet implemented)
    :param args:       arguments for GET command line, or for POST
    :param kw:         Keyword arguments to encode into POST body.
    :return:           (http_status, http_reason_phrase, http_headers, http_body)
                       as (integer, unicode, dict, str)

    Perform a client authenticated HTTPS request
    """
    if isinstance(host, unicode):
        host = host.encode('utf-8')
    uri = 'https://%s%s' % (ipautil.format_netloc(host, port), url)
    logging.info('sslget %r', uri)

    request_headers = {"Content-type": "application/xml",
                       "Accept": "application/xml"}
    if operation == "POST":
        if args != None:
            post = args
        elif kw != None:
            post = urlencode(kw)
            request_headers = {"Content-type": "application/x-www-form-urlencoded",
                               "Accept": "text/plain"}
    conn = None
    try:
        conn = nsslib.NSSConnection(host, port, dbdir=secdir)
        conn.set_debuglevel(0)
        conn.connect()
        conn.sock.set_client_auth_data_callback(nsslib.client_auth_data_callback,
                                                nickname,
                                                password, nss.get_default_certdb())
        if operation == "GET":
            url = url + "?" + args
            conn.request("GET", url)
        elif operation == "POST":
            conn.request("POST", url, post, request_headers)

        res = conn.getresponse()

        http_status = res.status
        http_reason_phrase = unicode(res.reason, 'utf-8')
        http_headers = res.msg.dict
        http_body = res.read()
    except Exception, e:
        raise NetworkError(uri=uri, error=str(e))
    finally:
        if conn is not None:
            conn.close()

    return http_status, http_reason_phrase, http_headers, http_body

def http_request(host, port, url, operation, args):
    """
    :param url: The URL to post to.
    :param operation:  GET, POST, (PUT and DELETE not yet implemented)
    :param args:       arguments for GET command line, or for POST
    :return:   (http_status, http_reason_phrase, http_headers, http_body)
                   as (integer, unicode, dict, str)

    Perform an HTTP request.
    """
    if isinstance(host, unicode):
        host = host.encode('utf-8')
    uri = 'http://%s%s' % (ipautil.format_netloc(host, port), url)
    logging.info('request %r', uri)
    request_headers = {"Content-type": "application/xml",
                   "Accept": "application/xml"}
    if operation == "POST":
        if args != None:
            post = args
        else:
            post = ""
    conn = httplib.HTTPConnection(host, port)
    try:
        if operation == "GET":
            if args != None:
                url = url + "?" + args
            conn.request("GET", url)
        elif operation == "POST":
            conn.request("POST", url, post, request_headers)

        res = conn.getresponse()

        http_status = res.status
        http_reason_phrase = unicode(res.reason, 'utf-8')
        http_headers = res.msg.dict
        http_body = res.read()
    except NSPRError, e:
        raise NetworkError(uri=uri, error=str(e))
    finally:
        if conn is not None:
            conn.close()

    logging.debug('request status %d', http_status)
    logging.debug('request reason_phrase %r', http_reason_phrase)
    logging.debug('request headers %s', http_headers)
    logging.debug('request body %r', http_body)

    return http_status, http_reason_phrase, http_headers, http_body

class kra:
    """
    Key Repository Authority backend plugin.
    """

    POST = "POST"
    GET = "GET"
    transport_cert = "byte array with transport cert"
    mechanism = nss.CKM_DES_CBC_PAD
    iv = "e4:bb:3b:d3:c3:71:2e:58"
    fullname = "kra"


    def __init__(self, work_dir, kra_host, kra_port, kra_nickname):
        # crypto
        self.sec_dir = work_dir
        self.pwd_file = work_dir + "/pwdfile.txt"
        self.transport_cert_nickname = kra_nickname
        self.mechanism = nss.CKM_DES3_CBC_PAD
        try:
            with open(self.pwd_file, "r") as f:
                self.password = f.readline().strip()
        except IOError:
            self.password = ''

        # set up key db for crypto functions
        try:
            nss.nss_init(self.sec_dir)
        except Exception, e:
            raise CertificateOperationError(error=_('Error in initializing certdb (%s)') \
                      + e.strerror)
        self.transport_cert = nss.find_cert_from_nickname(self.transport_cert_nickname)

        # DRM info
        self.kra_host = kra_host
        self.kra_agent_port = kra_port
        '''super(kra, self).__init__()'''

    def setup_contexts(self, mechanism, sym_key, iv):
        # Get a PK11 slot based on the cipher
        slot = nss.get_best_slot(mechanism)

        if sym_key == None:
            sym_key = slot.key_gen(mechanism, None, slot.get_best_key_length(mechanism))

        # If initialization vector was supplied use it, otherwise set it to None
        if iv:
            iv_data = nss.read_hex(iv)
            iv_si = nss.SecItem(iv_data)
            iv_param = nss.param_from_iv(mechanism, iv_si)
        else:
            iv_length = nss.get_iv_length(mechanism)
            if iv_length > 0:
                iv_data = nss.generate_random(iv_length)
                iv_si = nss.SecItem(iv_data)
                iv_param = nss.param_from_iv(mechanism, iv_si)
            else:
                iv_param = None

        # Create an encoding context
        encoding_ctx = nss.create_context_by_sym_key(mechanism, nss.CKA_ENCRYPT,
                                                     sym_key, iv_param)

        # Create a decoding context
        decoding_ctx = nss.create_context_by_sym_key(mechanism, nss.CKA_DECRYPT,
                                                     sym_key, iv_param)

        return encoding_ctx, decoding_ctx

    def debug(self, message, *args):
        print message % args

    def _request(self, url, port, operation, args):
        """
        :param url:        The URL to post to.
        :param port:       The port to post to
        :param operation:  GET/POST/PUT/DELETE (as supported by sslget)
        :param args:       A string containing arguments for a GET or POST request
        :return:           (http_status, http_reason_phrase, http_headers, http_body)
                            as (integer, unicode, dict, str)

        Perform an HTTP request.
        """
        return http_request(self.kra_host, port, url, operation, args)

    def _sslget(self, url, port, operation, args, **kw):
        """
        :param url:        The URL to post to.
        :param port:       The port to post to
        :param operation:  GET/POST/PUT/DELETE (as supported by sslget)
        :param args:       A string containing arguments for a GET or POST request
        :param kw:         Alternatively, keyword arguments to be form-encoded into POST body.
        :return:          (http_status, http_reason_phrase, http_headers, http_body)
                           as (integer, unicode, dict, str)

        Perform an HTTPS request
        """
        return https_request(self.kra_host, port, url, self.sec_dir, self.password,
							 self.ipa_certificate_nickname, operation, args, **kw)

    def symmetric_wrap(self, data, wrapping_key):
        """
        :param data:           Data to be wrapped
        :param wrapping_key    Symmetric key to wrap data

        Wrap (encrypt) data using the supplied symmetric key
        """
        encoding_ctx, decoding_ctx = self.setup_contexts(self.mechanism, wrapping_key, self.iv)
        wrapped_data = encoding_ctx.cipher_op(data) + encoding_ctx.digest_final()
        return wrapped_data

    def asymmetric_wrap(self, data, wrapping_cert):
        """
        :param data:           Data to be wrapped
        :param wrapping_cert    Public key to wrap data

        Wrap (encrypt) data using the supplied asymmetric key
        """

        return None

    def symmetric_unwrap(self, data, wrapping_key, iv=None):
        """
        :param data:           Data to be unwrapped
        :param wrapping_key    Symmetric key to unwrap data

        Unwrap (decrypt) data using the supplied symmetric key
        """
        if iv == None:
            iv = self.iv
        encoding_ctx, decoding_ctx = self.setup_contexts(self.mechanism, wrapping_key, iv)
        unwrapped_data = decoding_ctx.cipher_op(data) + decoding_ctx.digest_final()
        return unwrapped_data

    def get_parse_result_xml(self, xml_text, parse_func):
        '''
        :param xml_text:   The XML text to parse
        :param parse_func: The XML parsing function to apply to the parsed DOM tree.
        :return:           parsed result dict

        Utility routine which parses the input text into an XML DOM tree
        and then invokes the parsing function on the DOM tree in order
        to get the parsing result as a dict of key/value pairs.
        '''
        parser = etree.XMLParser()
        doc = etree.fromstring(xml_text, parser)
        result = parse_func(doc)
        self.debug("%s() xml_text:\n%s\nparse_result:\n%s" % (parse_func.__name__, xml_text, result))
        return result

    def create_archival_request(self, client_id, security_data, data_type):
        """
        :param :param client_id:  identifier to be used for this stored key
        :param security_data:     data blob (PKIArchiveOptions) containing passphrase
                                  or symmetric key to be archived
        :param data_type:         data type (symmetricKey, pass_phrase, asymmetricKey)
        :return doc:              xml doc with archival request
        """
        self.debug('%s.create_archival_request()', self.fullname)
        root = etree.Element("KeyArchivalRequest")
        client_id_element = etree.SubElement(root, "clientId")
        client_id_element.text = client_id
        wrapped_private_data_element = etree.SubElement(root, "wrappedPrivateData")
        wrapped_private_data_element.text = security_data
        data_type_element = etree.SubElement(root, "dataType")
        data_type_element.text = data_type
        return etree.ElementTree(root)

    def create_recovery_request(self, key_id, request_id, session_key, passphrase, nonce=None):
        """
        :param key_id:            identifier of key to be recovered
        :param request_id:        id for the recovery request
        :param session_key        session key wrapped in transport key
        :param passphrase         passphrase wrapped in session key
        :return doc:              xml doc with archival request

    	"""
        self.debug('%s.create_recovery_request()', self.fullname)
        root = etree.Element("KeyRecoveryRequest")
        if key_id != None:
            key_id_element = etree.SubElement(root, "keyId")
            key_id_element.text = key_id
        if request_id != None:
            request_id_element = etree.SubElement(root, "requestId")
            request_id_element.text = request_id
        if session_key != None:
            session_key_element = etree.SubElement(root, "transWrappedSessionKey")
            session_key_element.text = session_key
        if passphrase != None:
            passphrase_element = etree.SubElement(root, "sessionWrappedPassphrase")
            passphrase_element.text = passphrase
        if nonce != None:
            nonce_element = etree.SubElement(root, "nonceData")
            nonce_element.text = nonce
        return etree.ElementTree(root)

    def archive_security_data(self, client_id, security_data, data_type):
        """
        :param client_id:     identifier to be used for this stored key
        :param security_data: data blob (PKIArchiveOptions) containing passphrase
                              or symmetric key to be archived
        :param data_type:     data type (symmetricKey, pass_phrase, asymmetricKey)

        Archives security data packaged in a PKIArchiveOptions blob

        The command returns a dict with key/value pairs as defined in
        parse_key_request_info_xml().  These include the request_id of the created
        archival request, the status of the request, and the key_id of the archived
        key.
        """
        self.debug('%s.archive_security_data()', self.fullname)

        # check clientID and security data
        if ((client_id == None) or (security_data == None)):
            raise CertificateOperationError(error=_('Bad arguments to archive_security_data'))

        request = self.create_archival_request(client_id, security_data, data_type)

        # Call CMS
        http_status, http_reason_phrase, http_headers, http_body = \
            self._request('/kra/rest/agent/keyrequests/archive',
                         self.kra_agent_port,
                         self.POST,
                         etree.tostring(request.getroot(), encoding='UTF-8'))

        # Parse and handle errors
        if (http_status != 200):
            raise CertificateOperationError(error=_('Error in archiving request (%s)') % \
                      http_reason_phrase)

        parse_result = self.get_parse_result_xml(http_body, parse_key_request_info_xml)
        return parse_result

    def get_transport_cert(self, etag=None):
        """
        :param etag:    etag info for last cert retrieval from DRM

        Gets the transport certificate from the DRM

        The command returns a dict as defined in parse_certificate_data_xml()
        """
        self.debug('%s.get_transport_cert()', self.fullname)

        # Call CMS
        http_status, http_reason_phrase, http_headers, http_body = \
            self._request('/kra/rest/config/cert/transport',
                         self.kra_agent_port,
                         self.GET,
                         None)

        self.debug("headers: %s" , http_headers)
        # Parse and handle errors
        if (http_status != 200):
            raise CertificateOperationError(error=_('Error in archiving request (%s)') % \
                      http_reason_phrase)

        parse_result = self.get_parse_result_xml(http_body, parse_certificate_data_xml)
        return parse_result

    def list_security_data(self, client_id, key_state=None, next_id=None):
        """
        :param client_id:     identifier to be searched for
        :param key_state:     state for key (active, inactive, all)
        :param next_id:       id for starting key on next page (if more than one page)

        List security data matching the specified client id and state

        The command returns a dict as specified in parse_key_data_infos_xml().
        """
        self.debug('%s.list_security_data()', self.fullname)
        if client_id == None:
            raise CertificateOperationError(error=_('Bad argument to list_security_data'))
        get_args = "clientID=" + quote_plus(client_id)

        if key_state != None:
            get_args = get_args + "&status=" + quote_plus(key_state)

        if next_id != None:
            # currnently not implemented on server
            get_args = get_args + "&start=" + quote_plus(next_id)

        # Call CMS
        http_status, http_reason_phrase, http_headers, http_body = \
            self._request('/kra/rest/agent/keys',
                          self.kra_agent_port,
                          self.GET,
                          get_args)

        # Parse and handle errors
        if (http_status != 200):
            raise CertificateOperationError(error=_('Error in listing keys (%s)') % \
                      http_reason_phrase)

        parse_result = self.get_parse_result_xml(http_body, parse_key_data_infos_xml)
        return parse_result

    def list_key_requests(self, request_state=None, request_type=None, client_id=None,
                          next_id=None):
        """
        :param request_state:  state of request (pending, complete, cancelled, rejected, approved)
        :param request_type:   request type (enrollment, recovery)
        :param next_id:       id for starting key on next page (if more than one page)

        List security data matching the specified client id and state

        The command returns a dict as specified in parse_key_request_infos_xml().
        """
        self.debug('%s.list_key_requests()', self.fullname)
        get_args = ""

        if request_state != None:
            get_args = get_args + "&requestState=" + quote_plus(request_state)

        if request_type != None:
            get_args = get_args + "&requestType=" + quote_plus(request_type)

        if client_id != None:
            get_args = get_args + "&clientID=" + quote_plus(client_id)

        if next_id != None:
            # currnently not implemented on server
            get_args = get_args + "&start=" + quote_plus(next_id)

        # Call CMS
        http_status, http_reason_phrase, http_headers, http_body = \
            self._request('/kra/rest/agent/keyrequests',
                          self.kra_agent_port,
                          self.GET,
                          get_args)

        # Parse and handle errors
        if (http_status != 200):
            raise CertificateOperationError(error=_('Error in listing key requests (%s)') % \
                      http_reason_phrase)

        parse_result = self.get_parse_result_xml(http_body, parse_key_request_infos_xml)
        return parse_result

    def submit_recovery_request(self, key_id):
        """
        :param key_id: identifier of data to be recovered

        Create a recovery request for a passphrase or symmetric key

        The command returns a dict as described in the comments to
        parse_key_request_info_xml().  This data includes the request_id
        of the created recovery request
        """
        self.debug('%s.submit_recovery_request()', self.fullname)

        # check clientID and security data
        if key_id == None:
            raise CertificateOperationError(error=_('Bad argument to archive_security_data'))

        request = self.create_recovery_request(key_id, None, None, None)

        # Call CMS
        http_status, http_reason_phrase, http_headers, http_body = \
            self._request('/kra/rest/agent/keyrequests/recover',
                         self.kra_agent_port,
                         self.POST,
                         etree.tostring(request.getroot(), encoding='UTF-8'))

        # Parse and handle errors
        if (http_status != 200):
            raise CertificateOperationError(error=_('Error in archiving request (%s)') % \
                      http_reason_phrase)

        parse_result = self.get_parse_result_xml(http_body, parse_key_request_info_xml)
        return parse_result

    def check_request_status(self, request_id):
        """
        :param recovery_request_id:  identifier of key recovery request

        Check recovery request status

        The command returns a dict with these possible key/value pairs.
        Some key/value pairs may be absent

        +-----------------+---------------+-------------------------------------- +
        |result name      |result type    |comments                               |
        +=================+===============+=======================================+
        |request_status   |String         | status of request (pending, rejected, |
        |                 |               | approved)                             |
        +-----------------+---------------+---------------------------------------|
        |approvers_needed |int            | If pending, number of approvers       |
        |                 |               | needed                                |
        +-----------------+---------------+---------------------------------------+
        |approvers_list   |String         | list of approvers                     |
        +-----------------+---------------+---------------------------------------+
        """
        self.debug('%s.check_request_status()', self.fullname)

    def approve_recovery_request(self, request_id):
        """
        :param request_id:  identifier of key recovery request

        Approve recovery request
        """
        self.debug('%s.approve_recovery_request()', self.fullname)
        if request_id == None:
            raise CertificateOperationError(error=_('Bad argument to approve_recovery_request'))

        # Call CMS
        http_status, http_reason_phrase, http_headers, http_body = \
            self._request('/kra/rest/agent/keyrequests/' + request_id + '/approve',
                         self.kra_agent_port,
                         self.POST,
                         None)

        # Parse and handle errors
        if (http_status > 399):
            raise CertificateOperationError(error=_('Error in approving request (%s)') % \
                      http_reason_phrase)

    def reject_recovery_request(self, request_id):
        """
        :param recovery_request_id:  identifier of key recovery request

        Reject recovery request
        """
        self.debug('%s.reject_recovery_request()', self.fullname)
        if request_id == None:
            raise CertificateOperationError(error=_('Bad argument to reject_recovery_request'))

        # Call CMS
        http_status, http_reason_phrase, http_headers, http_body = \
            self._request('/kra/rest/agent/keyrequests/' + request_id + '/reject',
                         self.kra_agent_port,
                         self.POST,
                         None)

        # Parse and handle errors
        if (http_status > 399):
            raise CertificateOperationError(error=_('Error in rejecting request (%s)') % \
                      http_reason_phrase)

    def cancel_recovery_request(self, request_id):
        """
        :param recovery_request_id:  identifier of key recovery request

        Cancel recovery request
        """
        self.debug('%s.cancel_recovery_request()', self.fullname)
        if request_id == None:
            raise CertificateOperationError(error=_('Bad argument to cancel_recovery_request'))

        # Call CMS
        http_status, http_reason_phrase, http_headers, http_body = \
            self._request('/kra/rest/agent/keyrequests/' + request_id + '/cancel',
                         self.kra_agent_port,
                         self.POST,
                         None)

        # Parse and handle errors
        if (http_status > 399):
            raise CertificateOperationError(error=_('Error in cancelling request (%s)') % \
                      http_reason_phrase)

    def retrieve_security_data(self, recovery_request_id, passphrase=None):
        """
        :param recovery_request_id:  identifier of key recovery request
        :param passphrase:           passphrase to be used to wrap the data

        Recover the passphrase or symmetric key.  We require an approved
        recovery request.

        If a passphrase is provided, the DRM will return a blob that can be decrypted
        with the passphrase.  If not, then a symmetric key will be created to wrap the
        data for transport to this server.  Upon receipt, the data will be unwrapped
        and returned unencrypted.

        The command returns a dict with the values described in parse_key_data_xml(),
        as well as the following field

        +-----------------+---------------+-------------------------------------- +
        |result name      |result type    |comments                               |
        +=================+===============+=======================================+
        |data             |String         | Key data (either wrapped using        |
        |                 |               | passphrase or unwrapped)              |
        +-----------------+---------------+---------------------------------------+
    	"""
        self.debug('%s.retrieve_security_data()', self.fullname)

        if recovery_request_id == None:
            raise CertificateOperationError(error=_('Bad arguments to retrieve_security_data'))

        # generate symmetric key
        slot = nss.get_best_slot(self.mechanism)
        session_key = slot.key_gen(self.mechanism, None, slot.get_best_key_length(self.mechanism))

        # wrap this key with the transport cert
        public_key = self.transport_cert.subject_public_key_info.public_key
        wrapped_session_key = base64.b64encode(nss.pub_wrap_sym_key(self.mechanism, public_key, session_key))
        wrapped_passphrase = None
        if passphrase != None:
            # wrap passphrase with session key
            wrapped_session_key = base64.b64encode(self.symmetric_wrap(passphrase, session_key))

        request = self.create_recovery_request(None, recovery_request_id,
                                               wrapped_session_key,
                                               wrapped_passphrase)

        # Call CMS
        http_status, http_reason_phrase, http_headers, http_body = \
            self._request('/kra/rest/agent/keys/retrieve',
                         self.kra_agent_port,
                         self.POST,
                         etree.tostring(request.getroot(), encoding='UTF-8'))

        # Parse and handle errors
        if (http_status != 200):
            raise CertificateOperationError(error=_('Error in retrieving security data (%s)') % \
                      http_reason_phrase)

        parse_result = self.get_parse_result_xml(http_body, parse_key_data_xml)

        if passphrase == None:
            iv = nss.data_to_hex(base64.decodestring(parse_result['nonce_data']))
            parse_result['data'] = self.symmetric_unwrap(base64.decodestring(parse_result['wrapped_data']),
                                                         session_key, iv)

        return parse_result

    def recover_security_data(self, key_id, passphrase=None):
        """
        :param key_id:      identifier of key to be recovered
        :param passphrase:  passphrase to wrap key data for delivery outside of this server

        Recover the key data (symmetric key or passphrase) in a one step process.
        This is the case when only one approver is required to extract a key such that
        the agent submitting the recovery request is the only approver required.

        In this case, the request is automatically approved, and the KRA just returns the
        key data.

        This has not yet been implemented on the server
        """
        self.debug('%s.recover_security_data()', self.fullname)
        pass

""" Sample Test execution starts here """
import argparse

parser = argparse.ArgumentParser(description="Sample Test execution")
parser.add_argument('-d', default='/tmp/drmtest', dest='work_dir', help='Working directory')
parser.add_argument('--options', default='options.out', dest='options_file',
                    help='File containing test PKIArchiveOptions to be archived')
parser.add_argument('--symkey', default='symkey.out', dest='symkey_file',
                    help='File containing test symkey')
parser.add_argument('--host', default='localhost', dest='kra_host', help='DRM hostname')
parser.add_argument('-p', default='10080', type=int, dest='kra_port', help='DRM Port')
parser.add_argument('-n', default='DRM TransportCert Nickname', dest='kra_nickname',
                    help="DRM Nickname")

args = parser.parse_args()
work_dir = args.work_dir
kra_host = args.kra_host
kra_port = args.kra_port
kra_nickname = args.kra_nickname
options_file = args.options_file
symkey_file = args.symkey_file

test_kra = kra(work_dir, kra_host, kra_port, kra_nickname)

# list requests
requests = test_kra.list_key_requests()
print requests

# get transport cert
transport_cert = test_kra.get_transport_cert()
print transport_cert

# archive symmetric key
f = open(work_dir + "/" + options_file)
wrapped_key = f.read()
client_id = "Python symmetric key " + datetime.now().strftime("%Y-%m-%d %H:%M")
response = test_kra.archive_security_data(client_id, wrapped_key, "symmetricKey")
print response

# list keys with client_id
response = test_kra.list_security_data(client_id, "active")
print response

# create recovery request
key_id = response.keys()[0]
print key_id
response = test_kra.submit_recovery_request(key_id)
print response

# approve recovery request
request_id = response['request_id']
test_kra.approve_recovery_request(request_id)

# test invalid request
print "Testing invalid request ID"
try:
    response = test_kra.retrieve_security_data("INVALID")
    print "Failure: No exception thrown"
except CertificateOperationError, e:
    if 'Error in retrieving security data (Bad Request)' == e.error:
        print "Success: " + e.error
    else:
        print "Failure: Wrong error message: " + e.error

# retrieve key
response = test_kra.retrieve_security_data(request_id)
print response
print "retrieved data is " + base64.encodestring(response['data'])

# read original symkey from file
f = open(work_dir + "/" + symkey_file)
orig_key = f.read()
print "orig key is " + orig_key

if orig_key.strip() == base64.encodestring(response['data']).strip():
    print "Success: the keys match"
else:
    print "Failure: keys do not match"
