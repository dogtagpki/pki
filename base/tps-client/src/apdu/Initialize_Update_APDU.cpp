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
#include "apdu/Initialize_Update_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs Initialize Update APDU.
 */
TPS_PUBLIC Initialize_Update_APDU::Initialize_Update_APDU (BYTE key_version, BYTE key_index, Buffer &data)
{
    SetCLA(0x80);
    SetINS(0x50);
    SetP1(key_version);
    SetP2(key_index);
    SetData(data);
}

TPS_PUBLIC Initialize_Update_APDU::~Initialize_Update_APDU ()
{
}

TPS_PUBLIC Buffer &Initialize_Update_APDU::GetHostChallenge()
{
	return GetData();
}

TPS_PUBLIC APDU_Type Initialize_Update_APDU::GetType()
{
        return APDU_INITIALIZE_UPDATE;
}

TPS_PUBLIC void Initialize_Update_APDU::GetEncoding(Buffer &data)
{
    data += Buffer(1, m_cla);
    data += Buffer(1, m_ins);
    data += Buffer(1, m_p1);
    data += Buffer(1, m_p2);
    data += Buffer(1, (BYTE)m_data.size());
    data += Buffer(m_data, m_data.size());
} /* Encode */
