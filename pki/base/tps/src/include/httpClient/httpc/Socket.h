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

#ifndef __SOCKET_H
#define __SOCKET_H

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
 * Socket.h	1.000 06/12/2002
 * 
 * A NSPR implementation of socket
 *
 * @author  Surendra Rajam
 * @version 1.000, 06/12/2002
 */

class EXPORT_DECL Socket {
	friend class ServerSocket;
	friend class ServerConnection;
public:
	
	/**
	 * Constructor 
	 */
	Socket();

	/**
	 * Constructor - creates a socket connecting to the host and port
	 *
	 * @param	host	hostname to connect to
	 * @param	port	port of the machine
	 */
	Socket(const char* host, int port);

	/**
	 * Destructor
	 */
	virtual ~Socket();

public:

	/**
	 * Reads specified number of bytes from the socket. This is a blocking
	 * socket read with timeout.
	 *
	 * @param	buf		buffer to read into
	 * @param	size	number of bytes to read
	 * @param	timeout	timeout before the read terminates
	 * @return			number of bytes actually read
	 */
	int Read(void* buf, int size, long timeout);

	/**
	 * Writes specified number of bytes to the socket. This is a blocking
	 * socket write with timeout.
	 *
	 * @param	buf		buffer to write from
	 * @param	size	number of bytes to write
	 * @param	timeout	timeout before the write terminates
	 * @return			number of bytes actually written
	 */
	int Write(void* buf, int size, long timeout);

	/**
	 * Gets ip address for a specified socket
	 *
	 * @return	ip address
	 */
	const char* GetLocalIp();

	/**
	 * Gets port for a specified socket
	 *
	 * @return	port
	 */
	int GetLocalPort();

	/**
	 * Gets ip address of a connected peer
	 *
	 * @return	ip address
	 */
	const char* GetPeerIp();

	/**
	 * Gets port of a connected peer
	 *
	 * @return	ip address
	 */
	int GetPeerPort();

	/**
	 * Shuts down part of a full-duplex connection on a specified socket
	 *
	 * @param	how		the kind of disallowed operations on the socket
	 *					the possible values are :
	 *					PR_SHUTDOWN_RCV
	 *					PR_SHUTDOWN_SEND
	 *					PR_SHUTDOWN_BOTH
	 */
	void Shutdown(PRShutdownHow how);

protected:
	int Init(PRFileDesc* fd);

private:
	void CancelIO(PRInt32 err);

protected:
	PRFileDesc* m_fd;

private:
	char* m_localIp;
	char* m_peerIp;
	int m_localPort;
	int m_peerPort;
	bool m_initialized;
	PRLock* m_readLock;
	PRLock* m_writeLock;
};

#endif // __SOCKET_H


