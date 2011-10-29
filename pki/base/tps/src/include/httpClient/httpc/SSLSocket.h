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

#ifndef __SSL_SOCKET_H
#define __SSL_SOCKET_H

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
 * SSLSocket.h	1.000 06/12/2002
 * 
 * A Secure socket implementation based on NSPR / NSS 
 *
 * @author  Surendra Rajam
 * @version 1.000, 06/12/2002
 */

class EXPORT_DECL SSLSocket : public Socket {
	friend class SSLServerSocket;
public:
	/**
	 * Constructor
	 */
	SSLSocket();

	/**
	 * Destructor
	 */
	virtual ~SSLSocket();

private:
	/**
	 * Sets up this socket to behave as a SSL server
	 *
	 * @param	cert		server certificate object
	 * @param	privKey		private key structure
	 * @param	password	password to access DB
	 * @param	requestCert	whether to request cert from the client
	 * @return				0 on success, negative error code otherwise
	 *
	 */
	int SetupSSLServer(	CERTCertificate* serverCert, 
						SECKEYPrivateKey* privKey,
						SSLKEAType certKEA,
						int requestCert );
private:
	// server callbacks
	/**
	 * Specifies a certificate authentication callback function called 
	 * to authenticate an incoming certificate
	 *
	 * @param	arg			pointer supplied by the application 
	 *						(in the call to SSL_AuthCertificateHook) 
	 *						that can be used to pass state information
	 * @param	socket		pointer to the file descriptor for the SSL socket
	 * @param	checksig	PR_TRUE means signatures are to be checked and 
	 *						the certificate chain is to be validated
	 * @param	isServer	PR_TRUE means the callback function should 
	 *						evaluate the certificate as a server does, 
	 *						treating the remote end is a client
	 * @return				SECSuccess on success, SECFailure otherwise
	 *
	 */
	static SECStatus AuthCertificate( void* arg, 
									  PRFileDesc* socket,
									  PRBool checksig, 
									  PRBool isServer );

	/**
	 * Sets up a callback function to deal with a situation where the 
	 * SSL_AuthCertificate callback function has failed. This callback 
	 * function allows the application to override the decision made by 
	 * the certificate authorization callback and authorize the certificate 
	 * for use in the SSL connection. 
	 *
	 * @param	arg			The arg parameter passed to SSL_BadCertHook
	 * @param	socket		pointer to the file descriptor for the SSL socket
	 * @return				SECSuccess on success, SECFailure otherwise
	 */
	static SECStatus BadCertHandler( void* arg, 
								     PRFileDesc* socket );

	/**
	 * Sets up a callback function used by SSL to inform either a client 
	 * application or a server application when the handshake is completed
	 *
	 * @param	arg			The arg parameter passed to SSL_HandshakeCallback
	 * @param	socket		pointer to the file descriptor for the SSL socket
	 * @return				SECSuccess on success, SECFailure otherwise
	 */
	static SECStatus HandshakeCallback( PRFileDesc* socket, 
									    void* arg );

private:
	bool m_initializedAsServer;
};

#endif // __SSL_SOCKET_H


