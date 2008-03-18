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
#include "apdu/Install_Load_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs Install Load APDU.
 */
TPS_PUBLIC Install_Load_APDU::Install_Load_APDU (Buffer& packageAID, Buffer& sdAID, 
		unsigned int fileLen)
{
    SetCLA(0x84);
    SetINS(0xE6);
    SetP1(0x02);
    SetP2(0x00);

    Buffer inputData(packageAID.size() + sdAID.size() + 11);

    unsigned int i = 0; // offset
    ((BYTE*)inputData)[i++] = packageAID.size();
    inputData.replace(i, packageAID, packageAID.size());
    i += packageAID.size();

    ((BYTE*)inputData)[i++] = sdAID.size();
    inputData.replace(i, sdAID, sdAID.size());
    i += sdAID.size();

    ((BYTE*)inputData)[i++] = 0;

    ((BYTE*)inputData)[i++] = 6;

    ((BYTE*)inputData)[i++] = 0xEF;
    ((BYTE*)inputData)[i++] = 0x04;
    ((BYTE*)inputData)[i++] = 0xC6;
    ((BYTE*)inputData)[i++] = 0x02;
    fileLen += 24 + sdAID.size(); // !!! XXX

    ((BYTE*)inputData)[i++] = ((fileLen) >> 8) & 0xff;
    ((BYTE*)inputData)[i++] = fileLen & 0xff;

    ((BYTE*)inputData)[i++] = 0;

    SetData(inputData);
}

/**
 * Constructs Install Load APDU. Used when data was pre-constructed
 */
TPS_PUBLIC Install_Load_APDU::Install_Load_APDU (Buffer& data)
{
    SetCLA(0x84);
    SetINS(0xE6);
    SetP1(0x02);
    SetP2(0x00);
    SetData(data);
}

TPS_PUBLIC Install_Load_APDU::~Install_Load_APDU ()
{
}

TPS_PUBLIC APDU_Type Install_Load_APDU::GetType()
{
        return APDU_INSTALL_LOAD;
}
