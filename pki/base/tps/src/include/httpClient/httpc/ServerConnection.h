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

#ifndef __SERVER_CONNECTION_H
#define __SERVER_CONNECTION_H

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
 * ServerConnection.h	1.000 06/12/2002
 * 
 * This class handles server side connections. The accept happens on 
 * a separate thread and newly accepted connection are polled for 
 * read ready state. Once data is available on one or more connections
 * the listeners are notified about it.
 *
 * @author  Surendra Rajam
 * @version 1.000, 06/12/2002
 */

class EXPORT_DECL ServerConnection {
	friend class PollThread;
	friend class AcceptThread;
public:
	/**
	 *	Constructor
	 */
	ServerConnection();

	/**
	 *	Destructor
	 */
	virtual ~ServerConnection();

public:
	/**
	 * Registers a listener interface to notify on the connections
	 * 
	 * @param	listener	listener object
	 * @return				0 on success, negative error code otherwise
	 */
	int RegisterListener(ConnectionListener* listener);

	/**
	 * Listens for connections on a specified socket
	 *
	 * @param	host	host name / ip
	 * @param	port	listen port
	 * @return			0 on success, negative error code otherwise
	 */

	int Start(char* host, int port);

	/**
	 * Listens for connections on a specified socket for SSL connections
	 *
	 * @param	host		host name / ip
	 * @param	port		listen port
	 * @param	nickename	name of the server cert
	 * @param	password	password for DB
	 * @param	requestCert	request client certficate for authentication
	 * @return			0 on success, negative error code otherwise
	 */
	int Start( char* host, 
			   int port, 
			   const char* nickname, 
			   int requestcert);

	/**
	 * Closes the server connection
	 *
	 * @return	0 on success, negative error code otherwise
	 */
    int Shutdown();

	/**
	 * Releases the connection to the read pool. 
	 *
	 * @param	conn	a connection object
	 */
	void PollRead(Connection* conn);

	/**
	 * Releases the connection to the write pool. 
	 *
	 * @param	conn	a connection object
	 */
	void Release(Connection* conn);

	/**
	 * Gets a connection from the write pool. This connection should be 
	 * returned to the pool after writing.
	 *
	 * @return 0 on success, negative error code otherwise
	 */
	Connection* GetConnection();

	/**
	 * Returns the number of connections 
	 *
	 * @return	number of connections
	 */
	int GetCount();

	static void Poll(void* arg);
	static void Accept(void* arg);

protected:
	/**
	 * Protocol specific implementations should implement this
	 * function and return their own connection object
	 * 
	 * @return	a newly created connection
	 */
	virtual Connection* AcceptedConnection();

	const char* GetPeerHost(Connection* conn);
	int GetPeerPort(Connection* conn);

private:
	int InternalStart();
	void SetServerFlag(Connection* conn);
	PRFileDesc* GetFD( Connection* conn );
	void SetSocket(Connection* conn, Socket* socket);
	int UpdateWritePool(Connection* conn);

private:
	ServerSocket* m_server;
	ConnectionListener*	m_connectionListener;

	Pool* m_readPool;
	Pool* m_writePool;

	PRLock* m_readLock;
	PRLock* m_writeLock;

	PRBool m_threadInitialized;
	PRLock*	m_threadLock;
	PRCondVar* m_threadCondv;

	int	m_totalConnections;
	bool m_serverRunning;
};

#endif // __SERVER_CONNECTION_H


