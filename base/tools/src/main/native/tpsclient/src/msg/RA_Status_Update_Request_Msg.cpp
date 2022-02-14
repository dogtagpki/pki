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

#include "msg/RA_Status_Update_Request_Msg.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a Token PDU request.
 */
TPS_PUBLIC RA_Status_Update_Request_Msg::RA_Status_Update_Request_Msg (int status, const char *info)
{
    m_status = status;
    m_info = PL_strdup((char *) info);
}

/**
 * Destructs a Token PDU request.
 */
TPS_PUBLIC RA_Status_Update_Request_Msg::~RA_Status_Update_Request_Msg ()
{
    if( m_info != NULL ) {
        PL_strfree( m_info );
        m_info = NULL;
    }
}

/**
 * Retrieves the message type.
 */
TPS_PUBLIC RA_Msg_Type RA_Status_Update_Request_Msg::GetType ()
{
    return MSG_STATUS_UPDATE_REQUEST;
}

TPS_PUBLIC int RA_Status_Update_Request_Msg::GetStatus()
{
    return m_status;
}

TPS_PUBLIC char *RA_Status_Update_Request_Msg::GetInfo()
{
    return m_info;
}
