/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 */
/** BEGIN COPYRIGHT BLOCK
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA 
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include <string.h>
#include "httpClient/httpc/request.h"
#include "httpClient/httpc/engine.h"
#include "httpClient/httpc/PSPRUtil.h"
#include "engine/RA.h"
#include "main/Memory.h"

//-- static const char *DEBUG_MODULE = "httpclient";
//-- static const char *DEBUG_CLASS_NAME = "PSHttpRequest";

/**
 * Constructor
 * @param server The server to send request to 
 * @param uri The uri representing the request e.g /presence/start
 * @param prot HTTP10 or HTTP11 .
 * @param to Timeout ... ignore for now
 */

PSHttpRequest::PSHttpRequest(const PSHttpServer* server,
							 const char *uri,
							 HttpProtocol prot,
							 PRIntervalTime to) :  NetRequest(server) {
    //timeout = to;
	timeout = PR_INTERVAL_NO_TIMEOUT;
    _method = PL_strdup("GET");
    _uri = PL_strdup(uri);
    _proto = prot;
    _body = NULL;
    _bodyLength = -1;
    _expectedResponseLength = -1;
    _expectStandardBody = PR_FALSE;
    _expectDynamicBody = PR_FALSE;
    _hangupOk = PR_FALSE;
	_fileFd = NULL;
	nickName = NULL;
	_headers = new StringKeyCache("request",10*60);
}

/**
 * Destructor
 *
 */

PSHttpRequest::~PSHttpRequest() {
    if( _method != NULL ) {
        PL_strfree( _method );
        _method = NULL;
    }
    if( _uri != NULL ) {
        PL_strfree( _uri );
        _uri = NULL;
    }
    if( nickName != NULL ) {
        PL_strfree( nickName );
        nickName = NULL;
    }
    if( _fileFd != NULL ) {
        PR_Close( _fileFd );
        _fileFd = NULL;
    }
    if( _headers != NULL ) {
        delete _headers;
        _headers = NULL;
    }
}

/**
 * sets the request method for Http protocol
 * @param method GET /POST etc
 *
 */

PRBool PSHttpRequest::setMethod(const char *method) {
    if( _method != NULL ) {
        free( _method );
        _method = NULL;
    }
    _method = PL_strdup(method);
    return PR_TRUE;
}

void PSHttpRequest::setExpectedResponseLength(int size) {
    _expectedResponseLength = size;
}

void PSHttpRequest::setExpectStandardBody() {
    _expectStandardBody = PR_TRUE;
}

void PSHttpRequest::setExpectDynamicBody() {
    _expectDynamicBody = PR_TRUE;
}

PRBool PSHttpRequest::getExpectStandardBody() {
    return _expectStandardBody;
}

PRBool PSHttpRequest::getExpectDynamicBody() {
    return _expectDynamicBody;
}

int PSHttpRequest::getExpectedResponseLength() {
    return _expectedResponseLength;
}

/**
 * Returns the method to use
 *
 * @return GET /POST etc
 */

char * PSHttpRequest::getMethod() {
    return _method;
}

/**
 * Returns HTTP0 or HTTP11
 */
HttpProtocol HttpMessage::getProtocol() const {
    return proto;
}

/**
 * Adds an HTTP header to the request
 *
 * @param name header name
 * @param value  header value
 */
PRBool PSHttpRequest::addHeader(const char *name, const char *value) {
    char *dvalue = PL_strdup(value);
    CacheEntry *entry = _headers->Put(name,dvalue);
	if (entry == NULL ) {
        if( dvalue != NULL ) {
            PL_strfree( dvalue );
            dvalue = NULL;
        }
		return PR_FALSE;
	} else {
		return PR_TRUE;
	}
}

/**
 * Gets the value for a header for this HTTP request object
 *
 * @param name Name of the header
 * @return The value of the header in the request object
 */

const char * PSHttpRequest::getHeader(const char *name) {
    CacheEntry *entry = _headers->Get(name);
	return entry ? (char *)entry->GetData() : NULL;
}

/**
 * Sets the body of a POST message
 *
 * @param size Content length
 * @param body Content of the message; it is not copied
 * @return PR_TRUE if the Content-length header can be set
 */
PRBool PSHttpRequest::setBody(int size, const char* body) {
    char byteStr[12];

    sprintf(byteStr, "%d", size);
    if (!addHeader("Content-length", byteStr)) {
        return PR_FALSE;
	}

    _bodyLength = size;
    _body = (char *)body;

    return PR_TRUE;
}

PRBool PSHttpRequest::addRandomBody(int size) {
    char byteStr[12];

    sprintf(byteStr, "%d", size);
    if (!addHeader("Content-length", byteStr)) {
        return PR_FALSE;
	}

    _bodyLength = size;

    return PR_TRUE;
}

PRBool PSHttpRequest::useLocalFileAsBody(const char* fileName) {
    PRBool res  = PR_FALSE;
    PRFileInfo finfo;
	if (PR_GetFileInfo(fileName, &finfo) == PR_SUCCESS) {
		res = PR_TRUE;
		char byteStr[25];
		sprintf(byteStr, "%d", finfo.size);
		if (!addHeader("Content-length", byteStr)) {
			return PR_FALSE;
		}
		_bodyLength = finfo.size;
		_fileFd = PR_Open(fileName, PR_RDONLY, 0);
		if (!_fileFd) {
			return PR_FALSE;
		}
    }

    return PR_TRUE;
}

/**
 * This function sends the HTTP request to the server. 
 * @param sock - the connection onto which the request is to be sent
 */

PRBool PSHttpRequest::send( PRFileDesc *sock ) {
    const char *hostname;
//--	static const char *DEBUG_METHOD_NAME = "send";
//-- 	DebugLogger *logger = DebugLogger::GetDebugLogger( DEBUG_MODULE );

    PRBool rv = PR_FALSE;
	if (!sock) {
		return rv;
	}

    char *data = NULL;

    if (_proto == HTTP11) {
        hostname = getHeader("Host");

        if (hostname == NULL) {
            // long port = _server->getPort();

            char address[100];
            PR_snprintf(address, 100, "%s:%d", _server->getAddr(),
              _server->getPort());
            addHeader("Host", address);
        }
    }

	// create the HTTP string "GET /presence/stop HTTP/1.0"
    char *path = strstr( _uri, "//" );
    if ( path ) {
        path = strchr( path + 2, '/' );
    }
    if ( !path ) {
        path = _uri;
    }
	data = PR_smprintf( "%s %s %s\r\n", _method, path,
                        HttpProtocolToString(_proto) );

    // Send HTTP headers
	char **keys;
	char *headerValue = NULL;
	int nKeys = _headers->GetKeys( &keys );
	for ( int i = 0 ; i < nKeys; i++ ) {
		CacheEntry *entry = _headers->Get( keys[i] );
		if (entry) {
			headerValue =  (char *)entry->GetData();
			//adds the headers name: value
			data = PR_sprintf_append(data,"%s: %s\r\n",keys[i],headerValue);
            if( headerValue != NULL ) {
                PL_strfree( headerValue );
                headerValue = NULL;
            }
		}
        entry = _headers->Remove(keys[i]);
        if( entry != NULL ) {
            delete entry;
            entry = NULL;
        }
        if( keys[i] != NULL ) {
            delete [] ( keys[i] );
            keys[i] = NULL;
        }
    }
    if( keys != NULL ) {
        delete [] keys;
        keys = NULL;
    }

    // Send terminator
	data = PR_sprintf_append(data,"\r\n");

	int len = PL_strlen(data);
	//send the data ..
	int bytes = PR_Send(sock, data, len, 0, timeout);
    if( data != NULL ) {
        PR_smprintf_free( data );
        data = NULL;
    }
	if ( bytes != len ) {
//-- 	    logger->Log( LOGLEVEL_SEVERE, DEBUG_CLASS_NAME,
//-- 					 DEBUG_METHOD_NAME,
                RA::Debug( LL_PER_PDU,
                           "PSHttpRequest::send: ",
                           "Error sending request -- PR_Send returned(%d) Msg=%s\n",
                           PR_GetError(),
                           "XXX" );
        return PR_FALSE;
    }

    if ( _fileFd ) {
        // Send body from file
		PRInt32 bytesSent = PR_TransmitFile(sock, _fileFd, 0, 0, 
											PR_TRANSMITFILE_KEEP_OPEN, 
											timeout);
		if ( bytesSent < 0 ) {
//-- 			logger->Log( LOGLEVEL_SEVERE, DEBUG_CLASS_NAME,
//-- 						 DEBUG_METHOD_NAME,
                    RA::Debug( LL_PER_PDU,
                               "PSHttpRequest::send: ",
                               "Error sending request\n" );
			return PR_FALSE;
		}
    } else if (_bodyLength > 0) {
        // Send internally stored body
        char *allocated = NULL;
        if ( !_body ) {
            // Send a generated pattern
            _body = allocated = new char[_bodyLength];
            for ( int index = 0; index < _bodyLength; index++ ) {
				_body[index] = (unsigned char)(index %256);
            }
        }
        int sentBytes = 0;
        char *toSend = _body;
        for ( int i = _bodyLength; i > 0; i -= sentBytes ) {
            sentBytes = PR_Send( sock, toSend, i, 0, timeout );
            if ( sentBytes < 0 ) {
//--                 logger->Log( LOGLEVEL_SEVERE, DEBUG_CLASS_NAME,
//--                              DEBUG_METHOD_NAME,
                      RA::Debug( LL_PER_PDU,
                                 "PSHttpRequest::send: ",
                                 "Error sending request in PR_Send\n" );
                return PR_FALSE;
            }
            toSend += sentBytes;
        }
        if ( allocated ) {
            if( _body != NULL ) {
                delete [] _body;
                _body = NULL;
            }
        }
    }

    return PR_TRUE;
}

/**
 * Sets the nickname for the client cert to be send to the server
 * @param certName Nickname of the cert in the cert db
 */
void PSHttpRequest::setCertNickName(const char *certName) {
	nickName = PL_strdup(certName);
}

/**
 * Gets the nickname for the client cert
 * @return certName Nickname of the cert in the cert db
 */
char * PSHttpRequest::getCertNickName() {
	return nickName;
}

void PSHttpRequest::setHangupOk() {
    _hangupOk = PR_TRUE;
}

PRBool PSHttpRequest::isHangupOk() {
    return(_hangupOk);
}


/**
 * returns PR_TRUE if ssl is enabled for this request
 */
PRBool NetRequest::isSSL() const {
  return SSLOn;
}

/**
 * enable/disable SSL for the request
 */
void NetRequest::setSSL(PRBool SSLstate) {
  SSLOn=SSLstate;
}

/** 
* Constructor for NetRequest class. This is a superclass of httprequest class
* @param server The server to which the request is to be send
*/
NetRequest :: NetRequest(const PSHttpServer* server) {
    _server = server;
    timeout = Engine::globaltimeout;
    SSLOn=PR_FALSE;
    if (server)
        SSLOn=server->isSSL();
    handshake = PR_FALSE;
    cipherCount = 0;
    cipherSet = NULL;

}

/** 
* Returns the current configured timeout
*/
PRIntervalTime NetRequest :: getTimeout() const {
    return timeout;
}
