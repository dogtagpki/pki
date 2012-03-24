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

#ifndef __PSCRYPT_H__
#define __PSCRYPT_H__

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
 *  Encrypt/Decrypt
 */

class EXPORT_DECL PSCrypt {
private:
    /**
     * Constructor 
     */
    PSCrypt( );
    /**
     * Destructor 
     */
    virtual ~PSCrypt();

public:
    /**
     * Retuns the decrypted string
     * Assumption: The input string is base64 encoded
     * Assumption: Caller has to free the returned string using free
     * @param base64 encoded string to be decrypted
     * @param decrypted upon return, string in ascii
	 * @return 0 on success, -1 on failure
     */
    static int Decrypt (const char* encrypted, char** decrypted);

    /**
     * Retuns the encrypted string in base64
     *
	 * Assumption: Caller has to free the returned string using free
     * @param  text to encrypt
     * @param  encrypted upon return, text in base64
	 * @return 0 on success, -1 on failure
     */
    static int Encrypt(const char* text, char** encrypted);
};

#endif /* __PSCRYPT_H__ */

