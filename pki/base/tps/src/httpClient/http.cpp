/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
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

#include "httpClient/httpc/http.h"
#include "httpClient/httpc/engine.h"
#include "httpClient/httpc/request.h"
#include "httpClient/httpc/response.h"
//-- #include "httpClient/httpc/DebugLogger.h"
//-- #include "httpClient/httpc/ErrorLogger.h"
#include "httpClient/httpc/PSPRUtil.h"
#include "httpClient/httpc/Defines.h"
#include "engine/RA.h"
#include "main/Memory.h"


//-- static const char *DEBUG_MODULE = "httpclient";
//-- static const char *DEBUG_CLASS_NAME = "PSHttpServer";

/**
 * Constructor
 * @param addr The hostname:port of the server to connect to. The default
 * port is 80
 * @param af The protocol family like PR_AF_INET
 */
PSHttpServer::PSHttpServer(const char *addr, PRUint16 af) {
    SSLOn = PR_FALSE;
    PRUint16  port = 80;
//--	static const char *DEBUG_METHOD_NAME = "Constructor";
//-- 	DebugLogger *logger = DebugLogger::GetDebugLogger( DEBUG_MODULE );

    char *pPort;


    _addr = NULL;
//  if( _addr != NULL ) {
//      PL_strfree( _addr );
//      _addr = NULL;
//  }

    if (addr) {
        _addr = PL_strdup(addr); 
    }

    pPort = PL_strchr(_addr, ':');
    if (pPort) {
        *pPort = '\0';
        port = (PRUint16)  atoi(++pPort);
    }

    /* kludge for doing IPv6 tests on localhost */
    if (!PL_strcmp(_addr, "ip6-localhost") && (af == PR_AF_INET6)) {
         PL_strcpy(_addr, "::1");
    }

//    PR_InitializeNetAddr(PR_IpAddrNull, port, &_netAddr);

    if (PR_StringToNetAddr(_addr, &_netAddr) == PR_FAILURE) {
        char buf[2000];
        PRHostEnt ent;

        RA::Debug( LL_PER_PDU,
                                   "PSHttpServer::PSHttpServer ",
                                   " host %s port %d ",_addr,port );
        PR_InitializeNetAddr(PR_IpAddrNull, port, &_netAddr);
        if (PR_GetIPNodeByName(_addr, af, PR_AI_DEFAULT,
							   buf, sizeof(buf), &ent) == PR_SUCCESS) {
            PR_EnumerateHostEnt(0, &ent, port, &_netAddr);
        } else {
//-- 		    ErrorLogger::GetErrorLogger()->Log(
//--                 LOGLEVEL_SEVERE, PR_GetError(),
              RA::Debug( LL_PER_PDU,
                         "PSHttpServer::PSHttpServer: ",
                         "PR_GetIPNodeByName returned error %d [%s] for "
                         "address %s",
                         PR_GetError (),
                         "XXX",
                         addr );
//-- 		    logger->Log( LOGLEVEL_SEVERE, DEBUG_CLASS_NAME,
//-- 						 DEBUG_METHOD_NAME,
                    RA::Debug( LL_PER_PDU,
                               "PSHttpServer::PSHttpServer: ",
                               "PR_GetIPNodeByName returned error %d [%s] for "
                               "address %s",
                               PR_GetError(),
                               "XXX",
                               addr );
        }
    }
}

/**
 * Destructor of the Httpserver class 
 */
PSHttpServer::~PSHttpServer() {
    if( _addr != NULL ) {
        PL_strfree( _addr );
        _addr = NULL;
    }
}

/**
 * Turns SSL on or off for the connection
 * @param SSLstate PR_TRUE to make an SSL connection
 */
void PSHttpServer::setSSL(PRBool SSLstate) {
  SSLOn = SSLstate;
}

/**
 * Returns the current SSL state for this PSHttpServer object
 * @return PR_TRUE if SSL is enabled else PR_FALSE
 */
PRBool PSHttpServer::isSSL() const {
  return SSLOn;
}

/**
 * Returns the IP address of the HTTP server
 * @return IP address of the server as a long
 */

long PSHttpServer::getIp() const {
    return _netAddr.inet.ip;
}

/**
 * Returns the port for the HTTP server
 * @return port of the server
 */

long PSHttpServer::getPort() const {
    return (long)  PR_ntohs(_netAddr.inet.port);
}

/**
 * Returns the server IP address as a string
 * @return server address as string
*/
const char * PSHttpServer::getAddr() const {
    return _addr;
}

/**
 * Gets the server addr as a PR_NetAddr structure
 * @param addr PR_netaddr struct in which server address is returned
 */
void PSHttpServer::getAddr(PRNetAddr *addr) const {
    memcpy(addr, &_netAddr, sizeof(_netAddr));
}

/**
 * Fets the protocol as string: "HTTP/1.0" "HTTP/1.1" etc
 * @return Protocol string
 */
const char *HttpProtocolToString(HttpProtocol proto) {
    switch(proto) {
        case HTTP09:
            return "";
        case HTTP10:
            return "HTTP/1.0";
        case HTTP11:
            return "HTTP/1.1";
        case HTTPBOGUS:
            return "BOGO-PROTO";
        case HTTPNA:
			return NULL;
    }

    return NULL;
}

/**
* Constructor for HttpMessage. This is a base class for PSHttpRequest
*/
HttpMessage :: HttpMessage(long len, const char* buf) {
    firstline = NULL;
    cl = 0;
    proto = HTTPNA;

    // search for the first line
    int counter=0;
    PRBool found = PR_FALSE;
    while ( ( (counter++<len) && (PR_FALSE == found) ) ) {
        if (buf[counter] != '\n') {
            continue;
		}
        found = PR_TRUE;
    }

    // extract the first line
    if (PR_TRUE == found) {
        firstline=new char[counter+1];
        memcpy(firstline, buf, counter);
        firstline[counter] = '\0';
    }
}

HttpMessage :: ~HttpMessage() {
    if( firstline != NULL ) {
        delete firstline;
        firstline = NULL;
    }
}

/*SecurityProtocols :: SecurityProtocols(PRBool s2, PRBool s3, PRBool t)
{
    ssl2 = s2;
    ssl3 = s3;
    tls = t;
};

const SecurityProtocols& SecurityProtocols :: operator = (const RWTPtrSlist<char>& protlist)
{
    ssl2 = PR_FALSE;
    ssl3 = PR_FALSE;
    tls = PR_FALSE;
    PRInt32 i;
    for (i = 0;i<protlist.entries();i++)
    {
        if (0 == strcmp(protlist.at(i), "SSL2"))
        {
            ssl2 = PR_TRUE;
        };
        if (0 == strcmp(protlist.at(i), "SSL3"))
        {
            ssl3 = PR_TRUE;
        };
        if (0 == strcmp(protlist.at(i), "TLS"))
        {
            tls = PR_TRUE;
        };
    };
    return *this;
};

const SecurityProtocols& SecurityProtocols :: operator = (const SecurityProtocols& rhs)
{
    ssl2 = rhs.ssl2;
    ssl3 = rhs.ssl3;
    tls = rhs.tls;
    return *this;
};
*/


PRBool PSHttpServer::putFile(const char* localFile,
							 const char* remoteUri) const {
    PSHttpRequest request(this, remoteUri, HTTP10, Engine::globaltimeout);
    request.setMethod("PUT");
    request.useLocalFileAsBody(localFile);

    PRBool rv = _putFile(request);
    return rv;
}

PRBool PSHttpServer::putFile(const char *uri, int size) const {
    PSHttpRequest request(this, uri, HTTP10, Engine::globaltimeout);
    request.setMethod("PUT");
    request.addRandomBody(size);

    PRBool rv = _putFile(request);;
    return rv;
}

PRBool PSHttpServer::_putFile(PSHttpRequest& request) const {
    HttpEngine engine;
    PRBool rv = PR_TRUE;

    PSHttpResponse* response = engine.makeRequest(request, *this);

    if (response) {
        int status = response->getStatus();
        if (status == 200 || status == 201 || status == 204) {
            rv = PR_TRUE;
        } else {
            rv = PR_FALSE;
        }
        if( response != NULL ) {
            delete response;
            response = NULL;
        }
    } else {
        rv = PR_FALSE;
	}
    return rv;
}

