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

#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

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
#include "authentication/AuthParams.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

#define TPS_AUTH_OK                       0
#define TPS_AUTH_ERROR_LDAP              -1
#define TPS_AUTH_ERROR_USERNOTFOUND      -2
#define TPS_AUTH_ERROR_PASSWORDINCORRECT -3


class Authentication
{
  public:
	  TPS_PUBLIC Authentication();
	  TPS_PUBLIC virtual ~Authentication();
  public:
          virtual int Authenticate(AuthParams *params);  
          virtual void Initialize(int index);
  public: 
          virtual const char *GetTitle(char *locale);
          virtual const char *GetDescription(char *locale);
          virtual int GetNumOfParamNames();
          virtual char *GetParamID(int index);
          virtual const char *GetParamName(int index, char *locale);
          virtual char *GetParamType(int index);
          virtual const char *GetParamDescription(int index, char *locale);
          virtual char *GetParamOption(int index);
          int GetNumOfRetries(); // retries if the user entered the wrong password/securid

  protected:
          int m_retries;
};

#endif /* AUTHENTICATION_H */
