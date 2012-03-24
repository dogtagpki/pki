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

#ifndef _STRING_UTIL_H
#define _STRING_UTIL_H

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
 * String utility functions
 */

class EXPORT_DECL StringUtil {
private:
	/**
	 * Constructor - can't be instantiated
	 */
	StringUtil() {}

	/**
	 * Destructor
	 */
	~StringUtil() {}

public:
	/**
	 * Normalizes a screen name
	 *
	 * @param raw The raw screen name
	 * @param normalized The normalized screen name (lower case, no spaces)
	 */
	static void NormalizeScreenName( const char *raw, char *normalized );

	/**
	 * Converts the string to lower case
	 *
	 * @param	raw		string to be converted
	 */
	static void ToLower(char* raw);
};

#endif // _STRING_UTIL_H
