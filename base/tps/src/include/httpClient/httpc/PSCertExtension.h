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

#ifndef _PS_CERT_EXTENSION_H
#define _PS_CERT_EXTENSION_H

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
 * Presence Server cert extension. This extension contains customer 
 * specific information as per the contract apart from host and port 
 * used by BIG service provider to send user updates.
 */

class EXPORT_DECL PSCertExtension {
public:
	/**
	 * Constructor - 
	 */
	PSCertExtension();

	/**
	 * Destructor
	 */
	~PSCertExtension();

public:
	/**
	 * Loads the extension data from the specified cert. This function 
	 * will also verify the validity these fields :
	 *		HOST_NAME		-	should not be NULL or ""
	 *		PORT_NUMBER		-	> 0 and <= 65535
	 *		MAX_USERS		-	>= 0
	 *
	 * @param	nickname	cert nickname which contains the extension
	 * return	0 on success, 
	 *			-1 if nickname is missing from the argument
	 *			-2 if unable to find the cert
	 *			-3 if the presence extension is mising
	 *			-4 if the required values (hostname, port, maxusers) are invalid
	 *			-5 if the cert is expired
	 */
	int Load(const char* nickname);

	/**
	 * Gets the service version number from the cert ext
	 *
	 * return	version number as specified in the cert
	 */
	int GetVersion();

	/**
	 * Gets the street address from the cert
	 *
	 * return	street address as specified in the cert ext
	 */
	const char* GetStreetAddress();

	/**
	 * Gets the telephone number from the cert
	 *
	 * return	telephone number as specified in the cert ext
	 */
	const char* GetTelephoneNumber();

	/**
	 * Gets the RFC822 name from the cert
	 *
	 * return	RFC822 name as specified in the cert ext
	 */
	const char* GetRFC822Name();

	/**
	 * Gets the IM id from the cert
	 *
	 * return	IM id as specified in the cert ext
	 */
	const char* GetID();

	/**
	 * Gets the hostname from the cert ext
	 *
	 * return	hostname as specified in the cert ext
	 */
	const char* GetHostName();

	/**
	 * Gets the port number from the cert ext
	 *
	 * return	port number as specified in the cert ext
	 */
	int GetPortNumber();

	/**
	 * Gets the max users allowed from the cert ext
	 *
	 * return	max users as specified in the cert ext
	 */
	int GetMaxUsers();

	/**
	 * Gets the service level from the cert ext
	 *
	 * return	service level as specified in the cert ext
	 */
	int GetServiceLevel();

private:
	int	m_version;
	char* m_streetAddress;
	char* m_telephoneNumber;
	char* m_rfc822Name;
	char* m_id;
	char* m_hostName;
	int	m_portNumber;
	int	m_maxUsers;
	int	m_serviceLevel;
};

#endif // _PS_CERT_EXTENSION_H

