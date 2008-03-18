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

#ifndef BASE_H
#define BASE_H

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

#include "nspr.h"

typedef unsigned char BYTE;

enum nsNKeyMsgEnum {
  VRFY_FAILURE,
  VRFY_SUCCESS,
  ENCODE_DER_PUBKEY_FAILURE,
  B64ENCODE_FAILURE,
  VFY_BEGIN_FAILURE,
  VFY_UPDATE_FAILURE,
  HTTP_REQ_EXE_FAILURE,
  HTTP_ERROR_RCVD,
  BASE64_DECODE_FAILURE,
  REQ_TO_CA_SUCCESS,
  MSG_INVALID
};

struct ReturnStatus {
  PRStatus status;
  nsNKeyMsgEnum statusNum;
};

#endif /* BASE_H */
