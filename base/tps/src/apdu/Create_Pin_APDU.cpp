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
#include "apdu/Create_Pin_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs CreatePIN APDU.
 * CLA    0x80
 * INS    0x40
 * P1     <Pin number>
 * P2     <Max # of allowed attempts>
 * lc     <data length>
 * DATA   <Pin Value>
 *
 * Connection requirement:
 *   Secure Channel
 *
 * Possible error Status Codes:
 *  9C 06 - unauthorized
 *  9C 10 - incorrect p1
 *  9C 0E - invalid parameter (data)
 * 
 * @param p1 Pin number: 0x00 - 0x07
 * @param p2 Max # of consecutive unsuccessful verifications
 *           before the PIN blocks.
 * @param data pin
 * @see APDU
 */
TPS_PUBLIC Create_Pin_APDU::Create_Pin_APDU (BYTE p1, BYTE p2, Buffer &data)
{
//    SetCLA(0xB0);
    SetCLA(0x84);
    SetINS(0x40);
    SetP1(p1);
    SetP2(p2);
    SetData(data);
}

TPS_PUBLIC Create_Pin_APDU::~Create_Pin_APDU ()
{
}

TPS_PUBLIC APDU_Type Create_Pin_APDU::GetType()
{
        return APDU_CREATE_PIN;
}
