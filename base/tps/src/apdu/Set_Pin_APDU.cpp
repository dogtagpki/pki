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
#include <string.h>
#include "apdu/APDU.h"
#include "apdu/Set_Pin_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs SetPin APDU.
 *
 * SecureSetPIN APDU format:
 * CLA    0x80
 * INS    0x04
 * P1     <Pin number>
 * P2     0x00
 * lc     <data length>
 * DATA   <New Pin Value>
 *
 * Connection requirement:
 *   Secure Channel
 *
 * Possible error Status Codes:
 *  9C 06 - unauthorized
 *
 * @param p1 Pin number: 0x00 - 0x07
 * @param p2 always 0x00
 * @param data pin
 * @see APDU
 */
TPS_PUBLIC Set_Pin_APDU::Set_Pin_APDU (BYTE p1, BYTE p2, Buffer &data)
{
    SetCLA(0x84);
    SetINS(0x04);
    SetP1(p1);
    SetP2(p2);
    SetData(data);
}

TPS_PUBLIC Set_Pin_APDU::~Set_Pin_APDU ()
{
}

TPS_PUBLIC Buffer &Set_Pin_APDU::GetNewPIN()
{
    return GetData();
}

TPS_PUBLIC APDU_Type Set_Pin_APDU::GetType()
{
        return APDU_SET_PIN;
}
