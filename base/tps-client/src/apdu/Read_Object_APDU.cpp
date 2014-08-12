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
#include "apdu/Read_Object_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs Read Object APDU. 
 *
 * ReadObject APDU format:
 * CLA    0x84
 * INS    0x56
 * P1     0x00
 * P2     0x00
 * lc     0x09
 * DATA   <Data Parameters>
 *
 * [DATA] Parameters are:
 *        Long Object ID;
 *        Long Offset
 *        Byte Data Size;
 *
 * Connection requirement:
 *   Secure Channel
 *
 * Possible error Status Codes:
 *  9C 06 - unauthorized
 *  9C 07 - object not found
 *
 * @param object_id as defined in APDU
 * @param offset
 * @param data
 * @see APDU
 */
TPS_PUBLIC Read_Object_APDU::Read_Object_APDU (BYTE *object_id, int offset, int len)
{
    SetCLA(0x84);
    SetINS(0x56);
    SetP1(0x00);
    SetP2(0x00);
    Buffer data;
    data = 
        Buffer(1, (BYTE)object_id[0]) +
        Buffer(1, (BYTE)object_id[1]) +
        Buffer(1, (BYTE)object_id[2]) +
        Buffer(1, (BYTE)object_id[3]) +
        Buffer(1,(BYTE)((offset>>24) & 0xff)) +
        Buffer(1,(BYTE)((offset>>16) & 0xff)) +
        Buffer(1,(BYTE)((offset>>8) & 0xff)) +
        Buffer(1,(BYTE)(offset & 0xff)) +
        Buffer(1, (BYTE)len);
    SetData(data);
}

TPS_PUBLIC Read_Object_APDU::~Read_Object_APDU ()
{
}

TPS_PUBLIC APDU_Type Read_Object_APDU::GetType()
{
	        return APDU_READ_OBJECT;
}

