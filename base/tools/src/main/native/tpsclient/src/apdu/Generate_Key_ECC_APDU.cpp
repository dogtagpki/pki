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
#include "apdu/Generate_Key_ECC_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs Generate Key ECC APDU.
 */
TPS_PUBLIC Generate_Key_ECC_APDU::Generate_Key_ECC_APDU (BYTE p1, BYTE p2, BYTE alg, int keysize, BYTE option,
BYTE type, Buffer &wrapped_challenge, Buffer &key_check)
{
    SetCLA(0x84);
    SetINS(0x0D);
    SetP1(p1);
    SetP2(p2);

    Buffer data1;

    data1 = Buffer(1,alg) + Buffer(1,(BYTE)(keysize/256)) +  Buffer(1,(BYTE)(keysize%256)) + Buffer(1,option) + Buffer(1,type) + Buffer(1,(BYTE)wrapped_challenge.size()) + Buffer(wrapped_challenge) + Buffer(1,(BYTE)key_check.size()); 
    
    if(key_check.size() > 0) { 
        data1 = data1 + Buffer(key_check); 
    }
    
    SetData(data1);

}

TPS_PUBLIC Generate_Key_ECC_APDU::~Generate_Key_ECC_APDU ()
{
}

TPS_PUBLIC APDU_Type Generate_Key_ECC_APDU::GetType()
{
        return APDU_GENERATE_KEY_ECC;
}
