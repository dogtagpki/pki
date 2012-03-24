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

#ifndef _URL_UTIL_H
#define _URL_UTIL_H

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
 * URL utility functions
 */

typedef enum {
	URL_TYPE_HTTP		= 1,
	URL_TYPE_HTTPS		= 2,
	URL_TYPE_LDAP		= 3,
	URL_TYPE_LDAPS		= 4,
	URL_TYPE_UNKNOWN	= 5
} UrlType;

class EXPORT_DECL URLUtil {
private:
	/**
	 * Constructor - can't be instantiated
	 */
	URLUtil() {}

	/**
	 * Destructor
	 */
	~URLUtil() {}

public:
	/**
	 * Parses the URL 
	 *
	 * @param url	url to parse
	 * @param type	protocol header type
	 * @param host	hostname from the url
	 * @param port	port number from the url
	 * @param path	uri from the url
	 * @return		0 on success, negative error code otherwise
	 */
	static int ParseURL( const char* url, 
						 int* type,
						 char** host, 
						 int* port, 
						 char** path );

private:
	static int ParseURLType(const char* url, int* type, int* hlen);
	static int ParseAtPort(const char* url, int* port, char** path);
	static int ParseAtPath(const char* url, char** path);
	static int GetPort(const char* url, int* port);
	static bool IsAsciiSpace(char c);
	static bool IsAsciiDigit(char c);
};

#endif // _URL_UTIL_H

