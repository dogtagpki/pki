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
#include "apdu/Load_File_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs Load File APDU.
 */
TPS_PUBLIC Load_File_APDU::Load_File_APDU (BYTE refControl, BYTE blockNum, Buffer& data)
{
    SetCLA(0x84);
    SetINS(0xE8);
    SetP1(refControl);
    SetP2(blockNum);

    SetData(data);
}

TPS_PUBLIC Load_File_APDU::~Load_File_APDU ()
{
}

TPS_PUBLIC APDU_Type Load_File_APDU::GetType()
{
        return APDU_LOAD_FILE;
}
