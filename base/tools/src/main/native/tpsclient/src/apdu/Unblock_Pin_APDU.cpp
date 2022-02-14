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
#include "apdu/Unblock_Pin_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs Unblock Pin APDU.
 */
TPS_PUBLIC Unblock_Pin_APDU::Unblock_Pin_APDU ()
{
    SetCLA(0x84);
    SetINS(0x02);
    SetP1(0x00);
    SetP2(0x00);
}

TPS_PUBLIC Unblock_Pin_APDU::~Unblock_Pin_APDU ()
{
}

TPS_PUBLIC APDU_Type Unblock_Pin_APDU::GetType()
{
	        return APDU_UNBLOCK_PIN;
}
