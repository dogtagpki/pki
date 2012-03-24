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

#ifndef RA_END_OP_MSG_H
#define RA_END_OP_MSG_H

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

#include "main/RA_Msg.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */


#define    NKEY_ERROR_NO_ERROR 0
#define    NKEY_ERROR_SNAC 1
#define    NKEY_ERROR_SEC_INIT_UPDATE 2
#define    NKEY_ERROR_CREATE_CARDMGR 3
#define    NKEY_ERROR_MAC_RESET_PIN_PDU 4
#define    NKEY_ERROR_MAC_CERT_PDU 5
#define    NKEY_ERROR_MAC_LIFESTYLE_PDU 6
#define    NKEY_ERROR_MAC_ENROLL_PDU 7
#define    NKEY_ERROR_READ_OBJECT_PDU 8
#define    NKEY_ERROR_BAD_STATUS 9
#define    NKEY_ERROR_CA_RESPONSE 10
#define    NKEY_ERROR_READ_BUFFER_OVERFLOW 11
#define    NKEY_ERROR_TOKEN_RESET_PIN_FAILED 12
#define    NKEY_ERROR_CONNECTION 13

#define    RESULT_GOOD       0
#define    RESULT_ERROR 1

class RA_End_Op_Msg : public RA_Msg
{
  public:
	  TPS_PUBLIC RA_End_Op_Msg(RA_Op_Type op, int result, int msg);
	  TPS_PUBLIC ~RA_End_Op_Msg();
  public:
	  TPS_PUBLIC RA_Msg_Type GetType();
  public:
	  TPS_PUBLIC RA_Op_Type GetOpType();
	  TPS_PUBLIC int GetResult();
	  TPS_PUBLIC int GetMsg();
  private:
	  RA_Op_Type m_op;
	  int m_result;
	  int m_msg;
};

#endif /* RA_BEGIN_OP_MSG_H */
