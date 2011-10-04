// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include <stdio.h>
#include "apdu/APDU.h"
#include "apdu/External_Authenticate_APDU.h"
#include "channel/Secure_Channel.h"
#include "engine/RA.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs External Authenticate APDU. This  allows
 * setting of the security level.
 */
TPS_PUBLIC External_Authenticate_APDU::External_Authenticate_APDU (Buffer &data,
						SecurityLevel sl)
{
    SetCLA(0x84);
    SetINS(0x82);
    SetP1(0x01);

    if (sl == SECURE_MSG_MAC_ENC) {
      SetP1(0x03);
//     RA::Debug("External_Authenticate_APDU::External_Authenticate_APDU",
	//	"Security level set to 3 - attempted =%d", (int)sl);
    } else if (sl == SECURE_MSG_NONE) {
      SetP1(0x00);
//     RA::Debug("External_Authenticate_APDU::External_Authenticate_APDU",
//		"Security level set to 0 - attempted =%d", (int)sl);
    } else { // default
      SetP1(0x01);
 //    RA::Debug("External_Authenticate_APDU::External_Authenticate_APDU",
//		"Security level set to 1 - attempted =%d", (int)sl);
    }

    SetP2(0x00);
    SetData(data);
}

TPS_PUBLIC External_Authenticate_APDU::~External_Authenticate_APDU ()
{
}

TPS_PUBLIC Buffer &External_Authenticate_APDU::GetHostCryptogram()
{
    return GetData();
}

TPS_PUBLIC APDU_Type External_Authenticate_APDU::GetType()
{
	        return APDU_EXTERNAL_AUTHENTICATE;
}

