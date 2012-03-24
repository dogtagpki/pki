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

#ifndef RA_ATTRIBUTESPEC_H
#define RA_ATTRIBUTESPEC_H

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

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

class AttributeSpec
{
  public:
	  AttributeSpec();
	  ~AttributeSpec();
  public:
	  static AttributeSpec *Parse(Buffer *b, int offset);
	  void SetAttributeID(unsigned long v);
	  unsigned long GetAttributeID();
	  void SetType(BYTE v);
	  BYTE GetType();
	  void SetData(Buffer data);
	  Buffer GetData();  // this gets entire AttributeSpec
	  Buffer GetValue(); // this gets AttributeValue
   public:
	  unsigned long m_id;
	  BYTE m_type;
	  Buffer m_data; // this contains AttributeValue
};

#endif /* RA_ATTRIBUTESPEC_H */
