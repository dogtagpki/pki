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

#ifndef __CONNECTION_H
#define __CONNECTION_H

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
 * Connection.h	1.000 06/12/2002
 * 
 * Base class for all connection types. A user should extend this class 
 * and provide its protocol specific implementation
 *
 * @author  Surendra Rajam
 * @version 1.000, 06/12/2002
 */

class EXPORT_DECL Connection {
	friend class ServerConnection;
public:
	/**
	 * Constructor
	 */
	Connection();

	/**
	 * Destructor
	 */
	virtual ~Connection();

public:
	/**
	 * Initiates a connection to a specified host.
	 *
	 * @param	host	server host name
	 * @param	port	server port
	 * @return			0 on success, negative error code otherwise
	 */
	int Connect(const char* host, int port);

	/**
	 * Reads specified number of bytes from the connection. The connection 
	 * is locked for the period it is being read.
	 *
	 * @param	buf		buffer to read into
	 * @param	size	number of bytes to read
	 * @param	timeout	timeout before the read terminates
	 * @return			number of bytes actually read
	 */
	int Read(void* buf, int size, long timeout);

	/**
	 * Writes specified number of bytes to the connection.  The connection 
	 * is locked for the period it is being written.
	 *
	 * @param	buf		buffer to write from
	 * @param	size	number of bytes to write
	 * @param	timeout	timeout before the write terminates
	 * @return			number of bytes actually written
	 */
	int Write(void* buf, int size, long timeout);

	/**
	 * Gets the status of the connection
	 *
	 * @return true if closed, false otherwise
	 */
	bool IsClosed();

	/**
	 * Closes the connection
	 */
	void Close();

protected:
	Socket* m_socket;

private:
	PRLock* m_lock;
	bool m_closed;
};

#endif // __CONNECTION_H

