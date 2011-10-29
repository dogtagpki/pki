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

#ifndef __SERVER_SOCKET_H
#define __SERVER_SOCKET_H

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
 * ServerSocket.h	1.000 06/12/2002
 * 
 * A NSPR implementation of ServerSocket 
 * 
 * @author  Surendra Rajam
 * @version 1.000, 06/12/2002
 */

class EXPORT_DECL ServerSocket {
public:

	/**
	 * Constructor - Creates a new TCP socket
	 *
	 * @param	host	host name / ip
	 * @param	port	a listen port
	 */
	ServerSocket(const char* host, int port);

	/**
	 * Constructor - Creates a new TCP socket
	 *
	 * @param	port	a listen port
	 */
	ServerSocket(int port);

	/**
	 * Desstructor
	 */
	virtual ~ServerSocket();

public:
	
	/**
	 * Binds the socket to the specified port and starts listening for
	 * connections. The first connection is accepted from the queue of 
	 * pending connections and creates a new socket for the newly accepted 
	 * connection. The accept is blocked with no time out in its own thread. 
	 *
	 * @return	a new socket for the newly accepted connection
	 */
	virtual Socket* Accept();

	/**
	 * Closes the server socket
	 */
    virtual void Shutdown();

protected:
	/**
	 * Internal method to call accept. Sub classes should override this
	 * to provide their own implementation for returned sockets.
	 *
	 * @return	a newly accepted socket
	 */
	virtual Socket* InternalAccept(PRFileDesc* fd);

protected:
	bool m_initialized;

private:
	PRFileDesc* m_fd;
	PRNetAddr m_addr;
	char* m_host;
	int m_port;
	int m_backlog;
};

#endif // __SERVER_SOCKET_H



