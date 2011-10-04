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

#ifndef _PS_PRUTIL_H
#define _PS_PRUTIL_H

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
 * NSPR related Utility functions
 */

// define a stuct to store the mesasge
struct tuple_str {
    PRErrorCode  errNum;
    const char * errString;
};

typedef struct tuple_str tuple_str;

#define ER2(a,b)   {a, b},
#define ER3(a,b,c) {a, c},


class EXPORT_DECL PSPRUtil {

private:
	/**
	 * Constructor - can't be instantiated
	 */
	PSPRUtil() {}

	/**
	 * Destructor
	 */
	~PSPRUtil() {}

public:
	/**
 	 * Returns a string corresponding to an NSPR or NSS error code
 	 *
 	 * @param errNum Error number from PR_GetError()
 	 * @retuns An immutable string, the empty string if the code is not known
	 */
	 static const char * GetErrorString (PRErrorCode errCode);

	
	/**
 	 * Returns an error string for the latest NSPR or NSS error
	 *
	 * @return An error string, or the empty string if there is no current
	 * NSPR or NSS error
	 */
	static const char * GetErrorString();


};

#endif // _PS_PRUTIL_H

