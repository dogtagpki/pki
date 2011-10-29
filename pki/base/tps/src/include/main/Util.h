/* --- BEGIN COPYRIGHT BLOCK ---
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
 * --- END COPYRIGHT BLOCK ---
 */

#ifndef RA_UTIL_H
#define RA_UTIL_H

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

#include "pk11func.h"
#include "main/Buffer.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

class Util
{
  public:
	  TPS_PUBLIC Util();
	  TPS_PUBLIC ~Util();
  public:
          TPS_PUBLIC static int ReadLine(PRFileDesc *f, char *buf, int buf_len, int *removed_return);
          TPS_PUBLIC static int ascii2numeric(char ch);
	  TPS_PUBLIC static char *Buffer2String (Buffer &data);
	  TPS_PUBLIC static Buffer *Str2Buf (const char *s);
	  TPS_PUBLIC static char *URLEncode (Buffer &data);
	  TPS_PUBLIC static char *URLEncodeInHex (Buffer &data);
	  TPS_PUBLIC static char *URLEncode (const char *data);
	  TPS_PUBLIC static char *URLEncode1 (const char *data);
	  TPS_PUBLIC static Buffer *URLDecode(const char *data);
	  TPS_PUBLIC static char *SpecialURLEncode (Buffer &data);
	  TPS_PUBLIC static Buffer *SpecialURLDecode(const char *data);
          TPS_PUBLIC static PRStatus GetRandomChallenge(Buffer &random);
          TPS_PUBLIC static PRStatus CreateKeySetData(
                             Buffer &key_set_version,
                             Buffer &old_kek_key, 
			     Buffer &new_auth_key, 
			     Buffer &new_mac_key, 
			     Buffer &new_kek_key, 
			     Buffer &output);
          TPS_PUBLIC static PRStatus ComputeCryptogram(PK11SymKey *key,
			  const Buffer &card_challenge, 
			  const Buffer &host_challenge,
			  Buffer &output);
	  TPS_PUBLIC static PRStatus ComputeMAC(PK11SymKey *key, 
			  Buffer &input, const Buffer &icv, 
			  Buffer &output);
	  TPS_PUBLIC static PRStatus ComputeKeyCheck(
			  const Buffer& newKey, Buffer& output);
          TPS_PUBLIC static PK11SymKey *DeriveKey(const Buffer& permKey,
		        const Buffer& hostChallenge,
	              	const Buffer& cardChallenge);
	  TPS_PUBLIC static PRStatus EncryptData(PK11SymKey *encSessionKey,
			  Buffer &input, Buffer &output);
	  TPS_PUBLIC static PRStatus EncryptData(Buffer &kek_key, 
			  Buffer &input, Buffer &output);
          TPS_PUBLIC static PK11SymKey *DiversifyKey(PK11SymKey *master, 
                          Buffer &data, PK11SlotInfo *slot);
	  TPS_PUBLIC static PRStatus DecryptData(Buffer &kek_key, 
			  Buffer &input, Buffer &output);
	  TPS_PUBLIC static PRStatus DecryptData(PK11SymKey* enc_key, 
			  Buffer &input, Buffer &output);
          TPS_PUBLIC static BYTE*    bool2byte(bool p);
};

#endif /* RA_UTIL_H */
