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
#include "apdu/Get_IssuerInfo_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs GetIssuer APDU.
 *
 * SecureGetIssuer APDU format:
 * CLA    0x84
 * INS    0xF6
 * P1     0x00
 * P2     0x00
 * lc     0xE0
 * DATA   <Issuer Info>
 *
 * Connection requirement:
 *   Secure Channel
 *
 * Possible error Status Codes:
 *  9C 06 - unauthorized
 *
 * @param p1 always 0x00
 * @param p2 always 0x00
 * @param data issuer info
 * @see APDU
 */
TPS_PUBLIC Get_IssuerInfo_APDU::Get_IssuerInfo_APDU ()
{
    SetCLA(0x84);
    SetINS(0xF6);
    SetP1(0x00);
    SetP2(0x00);
}

TPS_PUBLIC Get_IssuerInfo_APDU::~Get_IssuerInfo_APDU ()
{
}

TPS_PUBLIC APDU_Type Get_IssuerInfo_APDU::GetType()
{
        return APDU_GET_ISSUERINFO;
}

TPS_PUBLIC void Get_IssuerInfo_APDU::GetEncoding(Buffer &data)
{
    data += Buffer(1, m_cla);
    data += Buffer(1, m_ins);
    data += Buffer(1, m_p1);
    data += Buffer(1, m_p2);
    data += Buffer(1, 0xe0);
} /* Encode */

