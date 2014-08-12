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

#ifndef RA_MSG_H
#define RA_MSG_H

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

enum RA_Op_Type {
	OP_ENROLL = 1,
	OP_UNBLOCK = 2,
	OP_RESET_PIN = 3,
	OP_RENEW = 4,
	OP_FORMAT = 5
};

enum RA_Msg_Type {
	MSG_UNDEFINED = -1,
	MSG_BEGIN_OP = 2,
	MSG_LOGIN_REQUEST = 3,
	MSG_LOGIN_RESPONSE = 4,
	MSG_SECUREID_REQUEST = 5,
	MSG_SECUREID_RESPONSE = 6,
	MSG_ASQ_REQUEST = 7,
	MSG_ASQ_RESPONSE = 8,
	MSG_NEW_PIN_REQUEST = 11,
	MSG_NEW_PIN_RESPONSE = 12,
	MSG_TOKEN_PDU_REQUEST = 9,
	MSG_TOKEN_PDU_RESPONSE = 10,
	MSG_END_OP = 13,
	MSG_STATUS_UPDATE_REQUEST = 14,
	MSG_STATUS_UPDATE_RESPONSE = 15,
	MSG_EXTENDED_LOGIN_REQUEST = 16,
	MSG_EXTENDED_LOGIN_RESPONSE = 17
};

class RA_Msg
{
  public:
	  RA_Msg();
	  virtual ~RA_Msg();
  public:
	  virtual RA_Msg_Type GetType();
};

#endif /* RA_MSG_H */
