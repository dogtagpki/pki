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

#ifndef AUTHENTICATIONENTRY_H
#define AUTHENTICATIONENTRY_H

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

#include "authentication/Authentication.h"

class AuthenticationEntry
{
  public:
	  AuthenticationEntry();
	  virtual ~AuthenticationEntry();
  public: 
          void SetLibrary(PRLibrary* lib);
          PRLibrary *GetLibrary();
          void SetId(const char *id);
          char *GetId();
          void SetAuthentication(Authentication *auth);
          Authentication *GetAuthentication();
          void SetType(const char *type);
          char *GetType();

  private:
          PRLibrary *m_lib;
          char *m_Id;
          char *m_type;
          Authentication *m_authentication;
};

#endif /* AUTHENTICATIONENTRY_H */
