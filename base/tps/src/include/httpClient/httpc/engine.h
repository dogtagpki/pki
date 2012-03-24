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

#ifndef _HTTP_ENGINE_
#define _HTTP_ENGINE_

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
#include "httpClient/httpc/response.h"
#include "httpClient/httpc/request.h"

class __EXPORT Engine {
    public:
        Engine() {};
        ~Engine() {};

        PRFileDesc *_doConnect(PRNetAddr *addr, PRBool SSLOn = PR_FALSE,
							   const PRInt32* cipherSuite = NULL, 
                               PRInt32 count = 0, const char* nickname = NULL,
							   PRBool handshake = PR_FALSE,
                               /*const SecurityProtocols& secprots = SecurityProtocols() ,*/
							   const char *serverName ="localhost",
                               PRIntervalTime iv = PR_SecondsToInterval(30));
        static PRIntervalTime globaltimeout;
};


class __EXPORT HttpEngine: public Engine {
    public:
        HttpEngine() {};
        ~HttpEngine() {};

        PSHttpResponse *makeRequest( PSHttpRequest &request,
			 const PSHttpServer& server,
			 int timeout = 30, PRBool expectChunked = PR_FALSE);
};

PRBool __EXPORT InitSecurity(char* dbpath, char* certname, char* certpassword,
							 char * prefix ,int verify=1);
PRBool __EXPORT EnableCipher(const char* ciphername);
void  __EXPORT EnableAllSSL3Ciphers();
void  __EXPORT EnableAllTLSCiphers();
__EXPORT const char * nscperror_lookup(int error);

#endif
