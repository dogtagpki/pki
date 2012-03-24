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

#include "msg/RA_New_Pin_Request_Msg.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a new pin request for the token.
 */
TPS_PUBLIC RA_New_Pin_Request_Msg::RA_New_Pin_Request_Msg (int min_len, int max_len)
{
    m_min_len = min_len;
    m_max_len = max_len;
}


/**
 * Destructs a new pin request.
 */
TPS_PUBLIC RA_New_Pin_Request_Msg::~RA_New_Pin_Request_Msg ()
{
}

/**
 * Retrieves the message type.
 */
TPS_PUBLIC RA_Msg_Type RA_New_Pin_Request_Msg::GetType ()
{
    return MSG_NEW_PIN_REQUEST;
}

/**
 * Retrieves the minimium length required for the new password.
 */
TPS_PUBLIC int RA_New_Pin_Request_Msg::GetMinLen()
{
    return m_min_len;
}


/**
 * Retrieves the maximium length required for the new password.
 */
TPS_PUBLIC int RA_New_Pin_Request_Msg::GetMaxLen()
{
    return m_max_len;
}
