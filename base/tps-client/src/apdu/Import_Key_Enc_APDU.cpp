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
#include "apdu/Import_Key_Enc_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs Import Key Encrypted APDU.
 *
 * CLA 0x80
 * INS 0x0A
 * P1 private Key Number (0x00 -0x0F) - key slot number defined in CMS.cfg
 * P2 public Key Number (0x00 -0x0F) - key slot number defined in CMS.cfg
 * DATA:
 *   Wrapped Key DesKey
 *   Byte IV_Length
 *   Byte IV_Data
 *
 * This function allows the import of a key into the card by (over)-writing the Cardlet memory.  Object ID 0xFFFFFFFE needs to be initialized with a key blob before invocation of this function so that it can retrieve the key from this object. The exact key blob contents depend on the key's algorithm, type and actual import parameters.  The key's number, algorithm type, and parameters are specified by argumetns P1, P2, P3, and DATA.  Appropriate values for these are specified below:

[DATA]
Import Parameters:
...to be provided
 */
TPS_PUBLIC Import_Key_Enc_APDU::Import_Key_Enc_APDU (BYTE p1, BYTE p2,
							   Buffer& data)
{
    SetCLA(0x84);
    SetINS(0x0A);
    SetP1(p1);
    SetP2(p2);

    SetData(data);
}

TPS_PUBLIC Import_Key_Enc_APDU::~Import_Key_Enc_APDU ()
{
}

TPS_PUBLIC APDU_Type Import_Key_Enc_APDU::GetType()
{
        return APDU_IMPORT_KEY_ENC;
}
