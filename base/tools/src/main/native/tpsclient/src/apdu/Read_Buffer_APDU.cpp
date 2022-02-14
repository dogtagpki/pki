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
#include "apdu/Read_Buffer_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs Read Buffer APDU.
 */
TPS_PUBLIC Read_Buffer_APDU::Read_Buffer_APDU (int len, int offset)
{
    SetCLA(0x84);
    SetINS(0x08);
    SetP1(len);
    SetP2(0x00);
    Buffer data;
    data = Buffer(1,(BYTE)(offset/256)) + Buffer(1,(BYTE)(offset%256));
    SetData(data);
}

TPS_PUBLIC Read_Buffer_APDU::~Read_Buffer_APDU ()
{
}

TPS_PUBLIC APDU_Type Read_Buffer_APDU::GetType()
{
	        return APDU_READ_BUFFER;
}

TPS_PUBLIC int Read_Buffer_APDU::GetLen()
{
        return m_p1;
}

TPS_PUBLIC int Read_Buffer_APDU::GetOffset()
{
        return (((int)((BYTE*)m_data)[0]) << 8) + ((int)((BYTE*)m_data)[1]);
}
