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
#include "apdu/Format_Muscle_Applet_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs Format Muscle Applet APDU.
 */
TPS_PUBLIC Format_Muscle_Applet_APDU::Format_Muscle_Applet_APDU (
		unsigned short memSize, 
		Buffer &PIN0, BYTE pin0Tries, 
		Buffer &unblockPIN0, BYTE unblock0Tries, 
		Buffer &PIN1, BYTE pin1Tries, 
		Buffer &unblockPIN1, BYTE unblock1Tries, 
		unsigned short objCreationPermissions, 
		unsigned short keyCreationPermissions, 
		unsigned short pinCreationPermissions)
{
    SetCLA(0xB0);
    SetINS(0x2A);
    SetP1(0x00);
    SetP2(0x00);

    Buffer data; data.reserve(100);
    Buffer pin((BYTE *)"Muscle00", 8);
    data += pin.size();
    data += pin;

    pin = Buffer((BYTE*) PIN0, PIN0.size());
    data += pin0Tries; // pin tries
    data += unblock0Tries; // unblock tries
    data += pin.size();
    data += pin;

    pin = Buffer((BYTE*)unblockPIN0, unblockPIN0.size());
    data += pin.size();
    data += pin;

    pin = Buffer((BYTE*)PIN1, PIN1.size());
    data += pin1Tries; // pin tries
    data += unblock1Tries; // unblock tries
    data += pin.size();
    data += pin;

    pin = Buffer((BYTE*)unblockPIN1, unblockPIN1.size());
    data += pin.size();
    data += pin;

    data += (BYTE)0; data += (BYTE)0; // fluff

    data += (memSize >> 8) & 0xff;
    data += memSize & 0xff;

    data += (BYTE)(objCreationPermissions >> 8);
    data += (BYTE)(objCreationPermissions & 0xFF);
    data += (BYTE)(keyCreationPermissions >> 8);
    data += (BYTE)(keyCreationPermissions & 0xFF);
    data += (BYTE)(pinCreationPermissions >> 8);
    data += (BYTE)(pinCreationPermissions & 0xFF);

    SetData(data);
}

TPS_PUBLIC Format_Muscle_Applet_APDU::~Format_Muscle_Applet_APDU ()
{
}

TPS_PUBLIC APDU_Type Format_Muscle_Applet_APDU::GetType()
{
        return APDU_FORMAT_MUSCLE_APPLET;
}

TPS_PUBLIC void Format_Muscle_Applet_APDU::GetEncoding(Buffer &data)
{
    data += Buffer(1, m_cla);
    data += Buffer(1, m_ins);
    data += Buffer(1, m_p1);
    data += Buffer(1, m_p2);
    data += Buffer(1, (BYTE)m_data.size());
    data += Buffer(m_data, m_data.size());
} /* Encode */
