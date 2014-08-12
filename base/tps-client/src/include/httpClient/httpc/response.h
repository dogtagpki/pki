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

#ifndef _RESPONSE_H_
#define _RESPONSE_H_

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
#include "httpClient/httpc/request.h"

class __EXPORT RecvBuf
{
public:
    RecvBuf(const PRFileDesc *socket, int size, int timeout = 30);
    virtual ~RecvBuf();

    char getChar();
    void putBack();

    void setChunkedMode();
    int getAllContent();
    int getTimeout();

    char *get_content();
    int get_contentSize();

    class EndOfFile {};
    class EndOfChunking {};

private:
    char _getChar();
    PRBool _getBytes(int size);

    const PRFileDesc *_socket;
    int _allocSize;
    char *_buf;
    int _curPos;
    int _curSize;

    PRBool _chunkedMode;
    int _currentChunkSize;
    int _currentChunkBytesRead;
    PRIntervalTime _timeout;
    char *_content;
    int _contentSize;
};


class __EXPORT Response
{
    public:
        Response(const PRFileDesc *sock, NetRequest *request);

    protected:
        const PRFileDesc   *_socket;
        NetRequest		 *_request;
};


class __EXPORT PSHttpResponse: public Response
{
    public:
        PSHttpResponse( const PRFileDesc *sock,
                        PSHttpRequest *request );
        PSHttpResponse( const PRFileDesc *sock,
                        PSHttpRequest *request,
                        int timeout, PRBool expectChunked );
        virtual ~PSHttpResponse();
        virtual PRBool        processResponse();

		int			  getReturnCode();
        long          getStatus();
        char         *getStatusString();
        HttpProtocol  getProtocol();
        char         *getHeader(const char *name);
        int			  getHeaders(char ***keys);

        PRBool        checkKeepAlive(); // return true if we *expect* keepalive based on request
        PRBool        checkConnection();  // return true if connection is open

        long          getBodyLength();
        char          *getContent();
	void          freeContent();
	int getContentSize();
        char          *toString();

    protected:
        PSHttpRequest   *_request;
        int           _verifyStandardBody(RecvBuf &, int, PRBool);
        PRBool        _handleBody(RecvBuf &buf);
        void          _checkResponseSanity();

        HttpProtocol  _proto;
        char         *_protocol;
        int retcode;
        char         *_statusNum;
        char         *_statusString;

        int           _keepAlive;
        int           _connectionClosed;

        long          _bodyLength;

	PRBool        _expectChunked;
        PRBool        _chunkedResponse;

        StringKeyCache  *_headers;

        int           _timeout;
        char          *_content;
        int	 _contentSize;
};


#endif
