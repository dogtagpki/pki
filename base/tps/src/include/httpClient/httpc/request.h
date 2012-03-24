/* --- BEGIN COPYRIGHT BLOCK ---
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
 * --- END COPYRIGHT BLOCK ---
 */

#ifndef _REQUEST_H_
#define _REQUEST_H_

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

#include "httpClient/httpc/http.h"

// abstract request class
class __EXPORT NetRequest
{
    public:
        NetRequest(const PSHttpServer* server);
        PRBool         isSSL() const;
        void           setSSL(PRBool SSLstate);
        void           getAddr(PRNetAddr *addr);
        const char*    getAddr();
        const char*    getHost();
        const          PSHttpServer * getServer();
        void           setServer(PSHttpServer* _server);
        PRIntervalTime getTimeout() const;
        const PRInt32* cipherSet;
        PRInt32        cipherCount;
        PRBool         handshake;
//        SecurityProtocols secprots;

    protected:
        PRBool SSLOn;
        const PSHttpServer * _server;
        PRIntervalTime timeout;
        
};

// Netscape-style request
class __EXPORT PSHttpRequest: public HttpMessage, public NetRequest
{
public:
    PSHttpRequest(const PSHttpServer* server, const char *uri, HttpProtocol proto, PRIntervalTime to);
    virtual ~PSHttpRequest();

    // connection related stuff

    // set data on the request
    PRBool         setMethod(const char *method);
    PRBool         addHeader(const char *name, const char *value);
    PRBool         addRandomBody(int size);
    PRBool         useLocalFileAsBody(const char* fileName);
    PRBool         setBody(int size, const char* body);
    void           setExpectedResponseLength(int size);
    void           setExpectStandardBody();
    void           setExpectDynamicBody();
    void           setHangupOk();
    PRBool         isHangupOk();

    // get data about the request
    char           *getMethod();
    //HttpProtocol   getProtocol();
	const char	   *getHeader(const char *name);
    int            getExpectedResponseLength();
    PRBool         getExpectStandardBody();
    PRBool         getExpectDynamicBody();

    PRBool send(PRFileDesc *sock);
	void setCertNickName(const char *);
	char *getCertNickName();

private:
    char            *_method;
    char            *_uri;
    HttpProtocol     _proto;
    int              _bodyLength;
	char            *_body;
    char			*nickName;
	StringKeyCache	 *_headers;
    int              _expectedResponseLength;
    PRBool           _expectStandardBody;
    PRBool           _expectDynamicBody;
    PRBool           _hangupOk;
    PRFileDesc*      _fileFd;
};

#endif
