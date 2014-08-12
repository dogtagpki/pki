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

#ifndef HTTPCONNECTION_H
#define HTTPCONNECTION_H

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

#include "httpClient/httpc/response.h"
#include "httpClient/httpc/request.h"
#include "httpClient/httpc/engine.h"
#include "httpClient/httpc/http.h"
#include "ConnectionInfo.h"
#include "main/NameValueSet.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

class HttpConnection
{
  public:
//	  HttpConnection();
          TPS_PUBLIC HttpConnection(const char *id, ConnectionInfo *cinfo, int retries, int timeout,
            bool isSSL, const char *clientnickname, bool keepAlive, NameValueSet *headers);
	  TPS_PUBLIC virtual ~HttpConnection();

  public:
          TPS_PUBLIC int GetNumOfRetries(); // failover retries
          TPS_PUBLIC int GetTimeout();
          TPS_PUBLIC ConnectionInfo *GetFailoverList();
          TPS_PUBLIC char *GetId();
          TPS_PUBLIC bool IsSSL();
          TPS_PUBLIC char *GetClientNickname();
          TPS_PUBLIC bool IsKeepAlive();
          TPS_PUBLIC PSHttpResponse *getResponse(int index, const char *servletID, const char *body);
          TPS_PUBLIC PRLock *GetLock();
          TPS_PUBLIC int GetCurrentIndex();
          TPS_PUBLIC void SetCurrentIndex(int index);

  protected:
     int m_max_conn;
     ConnectionInfo *m_failoverList;
     int m_retries;
     int m_timeout;
     char *m_Id;
     bool m_isSSL;
     char *m_clientnickname;
     bool m_keepAlive;
     NameValueSet *m_headers;
     PRLock *m_lock;
     int m_curr;
};

#endif /* HTTPCONNECTION_H */
