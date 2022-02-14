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
#include "apdu/Import_Key_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs Import Key APDU.
 *
 * CLA 0x84
 * INS 0x32
 * P1 Key Number (0x00 -0x0F) - key slot number defined in CS.cfg
 * P2 0x00
 * P3 Import Parameters Length (6 bytes: 3 shorts if just for ACL)
 * DATA Import Parameters
 *
 * This function allows th eimport of a key into the card by (over)-writing the Cardlet memory.  Object ID 0xFFFFFFFE needs to be initialized with a key blob before invocation of this function so tha tit can retrieve the key from this object. The exact key blob contents depend on th ekey's algorithm, type and actual import parameters.  The key's number, algorithm type, and parameters are specified by argumetns P1, P2, P3, and DATA.  Appropriate values for these are specified below:

[DATA]
Import Parameters:
KeyACL ACL for the imported key;
Byte[] Additional parameters; // Optional
If KeyBlob's Encoding is BLOB_ENC_PLAIN(0x00), there are no additional parameters.
 */
TPS_PUBLIC Import_Key_APDU::Import_Key_APDU (BYTE p1)
{
    SetCLA(0x84);
    SetINS(0x32);
    SetP1(p1);
    SetP2(0x00);
    //    SetP3(p3);

    Buffer data;
    data = 
      Buffer(1, (BYTE)0xFF) +  // means "read allowed" by anyone
      Buffer(1, (BYTE) 0xFF) +
      Buffer(1, (BYTE) 0x40) + // means "write" allowed for RA only
      Buffer(1, (BYTE) 0x00) +
      Buffer(1, (BYTE) 0xFF) + // means "use" allowed for everyone
      Buffer(1, (BYTE) 0xFF);

    SetData(data);
}

TPS_PUBLIC Import_Key_APDU::~Import_Key_APDU ()
{
}

TPS_PUBLIC APDU_Type Import_Key_APDU::GetType()
{
        return APDU_IMPORT_KEY;
}
