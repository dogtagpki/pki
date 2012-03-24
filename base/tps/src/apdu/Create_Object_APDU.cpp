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
#include "apdu/Create_Object_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a Create Object APDU.  This APDU is usually sent right
 * before Write_Buffer_APDU is sent.  This APDU only creates an Object
 * on token, but does not actually writes object content until
 * Write_Buffer_APDU is sent.
 *
 * CreateObject APDU format:
 * CLA    0x84
 * INS    0x5a
 * P1     0x00
 * P2     0x00
 * lc     0x0e
 * DATA   <Object Parameters>
 *
 * [DATA] Object Parameters are:
 *        Long Object ID;
 *        Long Object Size;
 *        ObjectACL ObjectACL;
 *
 * Connection requirement:
 *   Secure Channel
 *
 * Possible error Status Codes:
 *  9C 06 - unauthorized
 *  9C 08 - object already exists
 *  9C 01 - insufficient memory on card to complete the operation
 *
 * NOTE:
 *     Observe that the PIN identity is hard-coded at n.2 for each
 *   permission. In Housekey, this is probably a non-issue, however,
 *   in housekey, do we not allow multiple people (presumably closely
 *   -related) to share one token with individual certs?  We should
 *   consider exposing this as an input param.
 *
 * @param object_id as defined in APDU
 * @param len length of object
 * @see APDU
 */
TPS_PUBLIC Create_Object_APDU::Create_Object_APDU (BYTE *object_id, BYTE *permissions, int len)
{
    SetCLA(0x84);
    SetINS(0x5a);
    SetP1(0x00);
    SetP2(0x00);
    Buffer data;
    data =
        /* Object ID */
        Buffer(1, (BYTE)object_id[0]) +
        Buffer(1, (BYTE)object_id[1]) +
        Buffer(1, (BYTE)object_id[2]) +
        Buffer(1, (BYTE)object_id[3]) +
        /* data length */
        Buffer(1, (BYTE)(len >> 24)) +
        Buffer(1, (BYTE)((len >> 16) & 0xff)) +
        Buffer(1, (BYTE)((len >> 8) & 0xff)) +
        Buffer(1, (BYTE)(len & 0xff)) +
        /* ACLs */

      /* should take from caller
        // read permission
        Buffer(1, (BYTE)0xFF) +  // means "read"  never allowed
        Buffer(1, (BYTE)0xFF) +

        // write permission
        Buffer(1, (BYTE)0x40) +  //means "write" for identity n.2 (PIN required)
        Buffer(1, (BYTE)0x00) +

        // delete permission
        Buffer(1, (BYTE)0x40) +  //means "delete" for identity n.2 (PIN) required
        Buffer(1, (BYTE)0x00);
      */

      Buffer(1, (BYTE) permissions[0]) +
      Buffer(1, (BYTE) permissions[1]) +
      Buffer(1, (BYTE) permissions[2]) +
      Buffer(1, (BYTE) permissions[3]) +
      Buffer(1, (BYTE) permissions[4]) +
      Buffer(1, (BYTE) permissions[5]);

    SetData(data);
}

TPS_PUBLIC Create_Object_APDU::~Create_Object_APDU ()
{
}

TPS_PUBLIC APDU_Type Create_Object_APDU::GetType()
{
      return APDU_CREATE_OBJECT;
}
