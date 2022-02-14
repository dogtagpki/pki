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

#ifndef RA_CONN_H
#define RA_CONN_H

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

#include <stdio.h>
#include "prio.h"
#include "RA_Token.h"
#include "main/RA_Msg.h"
#include "main/Buffer.h"
#include "apdu/APDU.h"

class RA_Conn
{
  public:
	  RA_Conn(char *host, int port, char *uri);
	  ~RA_Conn();
  public:
          int SendMsg(RA_Msg *msg);
          RA_Msg *ReadMsg();
          RA_Msg *ReadMsg(RA_Token *token);
          int Connect();
          int Close();
	  void setEncryption(bool encrypted);
	  bool isEncrypted();
  public:
	  APDU *CreateAPDU(RA_Token *tok, Buffer &data, Buffer &mac);
  private:
          char *m_host;
          int m_port;
          char *m_uri;
	  PRFileDesc *m_fd;
	  int m_read_header;
	  bool m_encrypted_channel;
};

#endif /* RA_MSG_H */
