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

#ifndef LDAP_AUTHENTICATION_H
#define LDAP_AUTHENTICATION_H

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

#include "main/Login.h"
#include "main/SecureId.h"
#include "main/RA_Session.h"
#include "authentication/Authentication.h"

class LDAP_Authentication : public Authentication
{
  public:
	  LDAP_Authentication();
	  ~LDAP_Authentication();
  public:
          int Authenticate(AuthParams *params);
          void Initialize(int index);
  public:
          bool IsSSL();
          char *GetHostPort();

  public:
          void GetHostPort(char **p, char **q);
          virtual const char *GetTitle(char *locale);
          virtual const char *GetDescription(char *locale);
          virtual int GetNumOfParamNames();
          virtual char *GetParamID(int index);
          virtual const char *GetParamName(int index, char *locale);
          virtual char *GetParamType(int index);
          virtual const char *GetParamDescription(int index, char *locale);
          virtual char *GetParamOption(int index);

  private:
          int m_index;
          bool m_isSSL;
          char *m_hostport;
          char *m_attributes;
          char *m_ssl;
          char *m_baseDN;
          char *m_bindDN;
          char *m_bindPwd;
          int m_connectRetries; // for failover
          ConnectionInfo *m_connInfo;
};
  extern "C" 
  {
     Authentication *GetAuthentication();
  };

#endif /* LDAP_AUTHENTICATION_H */
