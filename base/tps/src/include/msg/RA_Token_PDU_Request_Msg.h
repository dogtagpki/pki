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

#ifndef RA_TOKEN_PDU_REQUEST_MSG_H
#define RA_TOKEN_PDU_REQUEST_MSG_H

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

#include "main/Base.h"
#include "main/Buffer.h"
#include "apdu/APDU.h"
#include "main/RA_Msg.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

class RA_Token_PDU_Request_Msg : public RA_Msg
{
  public:
	  TPS_PUBLIC RA_Token_PDU_Request_Msg(APDU *apdu);
	  TPS_PUBLIC ~RA_Token_PDU_Request_Msg();
  public:
	  TPS_PUBLIC RA_Msg_Type GetType();
	  TPS_PUBLIC APDU *GetAPDU();
  private:
	  APDU *m_apdu;
};

#endif /* RA_TOKEN_PDU_REQUEST_MSG_H */
