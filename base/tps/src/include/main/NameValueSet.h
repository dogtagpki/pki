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

#ifndef NAME_VALUE_SET_H
#define NAME_VALUE_SET_H

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

#include "plhash.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

class NameValueSet
{
  public:
	  TPS_PUBLIC NameValueSet();
	  TPS_PUBLIC ~NameValueSet();
  public:
	  TPS_PUBLIC static NameValueSet *Parse(const char *s, const char *separator);
	  TPS_PUBLIC int IsNameDefined(const char *name);
	  TPS_PUBLIC void Remove(const char *name);
	  TPS_PUBLIC void Add(const char *name, const char *value);
	  TPS_PUBLIC char *GetValue(const char *name);
	  TPS_PUBLIC int Size();
	  TPS_PUBLIC char *GetNameAt(int pos);
	  TPS_PUBLIC int GetValueAsInt(const char *key);
	  TPS_PUBLIC int GetValueAsInt(const char *key, int def); 
          TPS_PUBLIC int GetValueAsBool(const char *key);
          TPS_PUBLIC int GetValueAsBool(const char *key, int def); 
          TPS_PUBLIC char *GetValueAsString(const char *key, char *def);  
          TPS_PUBLIC char *GetValueAsString(const char *key);

  private: 
	  PLHashTable *m_set;
};

#endif /* NAME_VALUE_SET_H */
