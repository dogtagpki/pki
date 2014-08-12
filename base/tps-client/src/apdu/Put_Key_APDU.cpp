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
#include "main/Buffer.h"
#include "apdu/APDU.h"
#include "apdu/Put_Key_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs Put Key APDU.
 */
TPS_PUBLIC Put_Key_APDU::Put_Key_APDU (BYTE p1, BYTE p2, Buffer &data)
{
    SetCLA(0x84);
    SetINS(0xd8);
    SetP1(p1);
    SetP2(p2);
    SetData(data);
}

TPS_PUBLIC Put_Key_APDU::~Put_Key_APDU ()
{
}

TPS_PUBLIC APDU_Type Put_Key_APDU::GetType()
{
        return APDU_PUT_KEY;
}
