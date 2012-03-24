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

#ifndef RA_PKCS11OBJ_H
#define RA_PKCS11OBJ_H

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
#include "main/ObjectSpec.h"
#include "main/Buffer.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

class PKCS11Obj
{
  public:
	  PKCS11Obj();
	  ~PKCS11Obj();
  public:
	  static PKCS11Obj *Parse(Buffer *b, int offset);
	  void SetFormatVersion(unsigned short v);
	  unsigned short GetFormatVersion();
	  void SetObjectVersion(unsigned short v);
	  unsigned short GetObjectVersion();
	  void SetCUID(Buffer CUID);
	  Buffer GetCUID();
	  void SetTokenName(Buffer tokenName);
	  Buffer GetTokenName();
	  Buffer GetData();
	  Buffer GetCompressedData();
	int GetObjectSpecCount();
	ObjectSpec *GetObjectSpec(int p);
	void AddObjectSpec(ObjectSpec *p);
	void RemoveObjectSpec(int p);
  public:
	unsigned short m_formatVersion;
	unsigned short m_objectVersion;
	Buffer m_CUID;
	Buffer m_tokenName;
#define MAX_OBJECT_SPEC 20
	ObjectSpec *m_objSpec[MAX_OBJECT_SPEC];
};

#endif /* RA_PKCS11OBj_H */
