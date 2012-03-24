// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cms/HttpConnection.h"
#include "main/Memory.h"
#include "main/NameValueSet.h"
#include "engine/RA.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a base class for HttpConnection
 */
TPS_PUBLIC HttpConnection::HttpConnection(const char *id, ConnectionInfo *cinfo, int retries, int timeout,
  bool isSSL, const char *nickname, bool keepAlive, NameValueSet *headers)
{
    m_failoverList = cinfo;
    m_retries = retries;
    m_timeout = timeout;
    m_Id = PL_strdup(id);
    m_isSSL = isSSL;
    m_clientnickname = PL_strdup(nickname);
    m_keepAlive = keepAlive;
    m_headers = headers;
    m_curr = 0;
    m_lock = PR_NewLock();
}

/**
 * Destructs processor.
 */
TPS_PUBLIC HttpConnection::~HttpConnection ()
{
    if( m_clientnickname != NULL ) {
        PL_strfree( m_clientnickname );
        m_clientnickname = NULL;
    }
    if( m_Id != NULL ) {
        PL_strfree( m_Id );
        m_Id = NULL;
    }
    if( m_failoverList != NULL ) {
        delete m_failoverList;
        m_failoverList = NULL;
    }
    if( m_headers != NULL ) {
        delete m_headers;
        m_headers = NULL;
    }
    if( m_lock != NULL ) {
        PR_DestroyLock( m_lock );
        m_lock = NULL;
    }
}

TPS_PUBLIC int HttpConnection::GetNumOfRetries() {
    return m_retries;
}

int HttpConnection::GetTimeout() {
    return m_timeout;
}

TPS_PUBLIC ConnectionInfo *HttpConnection::GetFailoverList() {
    return m_failoverList;
}

TPS_PUBLIC char *HttpConnection::GetId() {
    return m_Id;
}

TPS_PUBLIC bool HttpConnection::IsSSL() {
    return m_isSSL;
}

TPS_PUBLIC char * HttpConnection::GetClientNickname() {
    return m_clientnickname;
}

TPS_PUBLIC bool HttpConnection::IsKeepAlive() {
    return m_keepAlive;
}

TPS_PUBLIC PSHttpResponse *HttpConnection::getResponse(int index, const char *servlet, const char *body) {
    char *host_port;
    char uri[800];
    char *nickname;
    const char *httpprotocol;

    ConnectionInfo *failoverList = GetFailoverList();
    int len = failoverList->ConnectionInfo::GetHostPortListLen(); 
    if (index >= len) {
      index = len - 1; // use the last one
    }
    host_port= (failoverList->GetHostPortList())[index];

    if (IsSSL()) {
        httpprotocol = "https";
    } else {
        httpprotocol = "http";
    }

    PR_snprintf((char *)uri, 800,
      "%s://%s/%s",
      httpprotocol, host_port, servlet);

    RA::Debug("HttpConnection::getResponse", "Send request to host %s servlet %s", host_port, servlet);

    RA::Debug(LL_PER_PDU, "HttpConnection::getResponse", "uri=%s", uri);
    RA::Debug(LL_PER_PDU, "HttpConnection::getResponse", "host_port=%s", host_port);

    char *pPort = NULL;
    char *pPortActual = NULL;


    char hostName[512];

    /*
     * Isolate the host name, account for IPV6 numeric addresses.
     *
     */

    if(host_port)
        strncpy(hostName,host_port,512);

    pPort = hostName;
    while(1)  {
        pPort = strchr(pPort, ':');
        if (pPort) {
            pPortActual = pPort;
            pPort++;
        } else
            break;
    }

    if(pPortActual)
        *pPortActual = '\0';


    /*
    *  Rifle through the values for the host
    */

    PRAddrInfo *ai;
    void *iter;
    PRNetAddr addr;
    int family = PR_AF_INET;

    ai = PR_GetAddrInfoByName(hostName, PR_AF_UNSPEC, PR_AI_ADDRCONFIG);
    if (ai) {
        printf("%s\n", PR_GetCanonNameFromAddrInfo(ai));
        iter = NULL;
        while ((iter = PR_EnumerateAddrInfo(iter, ai, 0, &addr)) != NULL) {
            char buf[512];
            PR_NetAddrToString(&addr, buf, sizeof buf);
            RA::Debug( LL_PER_PDU,
                       "HttpConnection::getResponse: ",
                           "Sending addr -- Msg='%s'\n",
                           buf );
            family = PR_NetAddrFamily(&addr);
            RA::Debug( LL_PER_PDU,
                       "HttpConnection::getResponse: ",
                           "Sending family -- Msg='%d'\n",
                           family );
            break;
        }
        PR_FreeAddrInfo(ai);
        
    }

    PSHttpServer httpserver(host_port, family);
    nickname = GetClientNickname();
    if (IsSSL())
       httpserver.setSSL(PR_TRUE);
    else
       httpserver.setSSL(PR_FALSE);

    PSHttpRequest httprequest(&httpserver, uri, HTTP11, 0);
    if (IsSSL()) {
        httprequest.setSSL(PR_TRUE);
        if (nickname != NULL) {
            httprequest.setCertNickName(nickname);
        } else {
            return NULL;
        }
    } else
        httprequest.setSSL(PR_FALSE);

    httprequest.setMethod("POST");

    if (body != NULL) {
        httprequest.setBody( strlen(body), body);
    }

    httprequest.addHeader( "Content-Type", "application/x-www-form-urlencoded" );
    if (m_headers != NULL) {
        for (int i=0; i<m_headers->Size(); i++) {
            char *name = m_headers->GetNameAt(i);
            httprequest.addHeader(name, m_headers->GetValue(name));
        }
    }

    if (IsKeepAlive())
        httprequest.addHeader( "Connection", "keep-alive" );

    HttpEngine httpEngine;
    return httpEngine.makeRequest(httprequest, httpserver, (PRIntervalTime)GetTimeout(),
      PR_FALSE /*expectChunked*/);
}

TPS_PUBLIC PRLock * HttpConnection::GetLock() {
    return m_lock;
}

TPS_PUBLIC int HttpConnection::GetCurrentIndex() {
    return m_curr;
}

TPS_PUBLIC void HttpConnection::SetCurrentIndex(int index) {
    m_curr = index;
}
