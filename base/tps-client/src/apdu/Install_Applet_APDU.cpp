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
#include "apdu/Install_Applet_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs Install Applet APDU.
 */
TPS_PUBLIC Install_Applet_APDU::Install_Applet_APDU (Buffer &packageAID, Buffer &appletAID,
		BYTE appPrivileges, unsigned int instanceSize, unsigned int appletMemorySize)
{
    SetCLA(0x84);
    SetINS(0xE6);
    SetP1(0x0C);
    SetP2(0x00);

    Buffer data;
    data.reserve(32); // pre-allocate
    data += packageAID.size();
    data += packageAID;
    data += appletAID.size();
    data += appletAID;
    data += appletAID.size();
    data += appletAID;

    data += 0x01; // length of application privileges byte
    data += appPrivileges;

    Buffer installParams; installParams.reserve(6);
    installParams += 0xEF;
    installParams += 0x04;
    installParams += 0xC8;
    installParams += 0x02;

    installParams += (instanceSize>>8) & 0xff;
    installParams += instanceSize & 0xff;
    installParams += 0xC9;


    //installParams += 0x01;
    //installParams += (BYTE)0x00;

    //Now add some applet specific init data that the applet supports
    //Length of applet specific data

    installParams += 0x04;

    //Issuer info length.
    //Leave this to zero since TPS already writes phone home info to card.
    installParams += (BYTE)0x00;

    //Length of applet memory size
    installParams += (BYTE)0x02;

    // Applet memory block size

    installParams += (appletMemorySize>>8) & 0xff;
    installParams += appletMemorySize & 0xff;

    data += installParams.size();
    data += installParams;
    data += (BYTE) 0x00; // size of token return data

    SetData(data);
}

/**
 * Constructs Install Applet APDU.
 */
TPS_PUBLIC Install_Applet_APDU::Install_Applet_APDU (Buffer &data)
{
    SetCLA(0x84);
    SetINS(0xE6);
    SetP1(0x0C);
    SetP2(0x00);
    SetData(data);
}

TPS_PUBLIC Install_Applet_APDU::~Install_Applet_APDU ()
{
}

TPS_PUBLIC APDU_Type Install_Applet_APDU::GetType()
{
        return APDU_INSTALL_APPLET;
}
