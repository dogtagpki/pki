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

#ifndef __SSL_SERVER_SOCKET_H
#define __SSL_SERVER_SOCKET_H

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

/**
 * SSLServerSocket.h	1.000 06/12/2002
 * 
 * A Secure server socket implementation based on NSPR / NSS
 * 
 * @author  Surendra Rajam
 * @version 1.000, 06/12/2002
 */

class EXPORT_DECL SSLServerSocket : public ServerSocket {
public:
	/**
	 * Constructor 
	 */
	SSLServerSocket( const char* host, 
					 int port, 
					 const char* nickname,
					 int requestcert );

	/**
	 * Destructor 
	 */
	virtual ~SSLServerSocket();

public:
	/**
	 * Initializes cert and private key before calling base class
	 * Accept function.
	 */
	Socket* Accept();

private:
	/**
	 * Overrides base class function to create SSL sockets
	 *
	 * @return	a newly accepted SSL socket
	 */
	Socket* InternalAccept(PRFileDesc* fd);

private:
	char* m_nickName;
	int m_requestCert;
	CERTCertificate* m_serverCert;
	SECKEYPrivateKey* m_serverPrivKey;
	SSLKEAType m_certKEA;
};

#endif // __SSL_SERVER_SOCKET_H





