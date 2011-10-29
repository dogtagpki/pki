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

#ifndef RA_OBJECTSPEC_H
#define RA_OBJECTSPEC_H

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
#include "main/AttributeSpec.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

class ObjectSpec
{
  public:
	  ObjectSpec();
	  ~ObjectSpec();
  public:
	  static ObjectSpec *ParseFromTokenData(unsigned long objid, Buffer *b);
	  static ObjectSpec *Parse(Buffer *b, int offset, int *nread);
	  static void ParseAttributes(char *objectID, ObjectSpec *ObjectSpec, Buffer *b);
	  static void ParseCertificateAttributes(char *objectID, ObjectSpec *ObjectSpec, Buffer *b);
	  static void ParseKeyAttributes(char *objectID, ObjectSpec *ObjectSpec, Buffer *b);
	  static void ParseCertificateBlob(char *objectID, ObjectSpec *ObjectSpec, Buffer *b);

	  void SetObjectID(unsigned long v);
	  unsigned long GetObjectID();
	  void SetFixedAttributes(unsigned long v);
	  unsigned long GetFixedAttributes();
	  int GetAttributeSpecCount();
	  AttributeSpec *GetAttributeSpec(int p);
	  void AddAttributeSpec(AttributeSpec *p);
          void RemoveAttributeSpec(int p);
	  Buffer GetData();
  public:
	  unsigned long m_objectID;
	  unsigned long m_fixedAttributes;
#define MAX_ATTRIBUTE_SPEC 30
	  AttributeSpec *m_attributeSpec[MAX_ATTRIBUTE_SPEC];
};

#endif /* RA_OBJECTSPEC_H */
