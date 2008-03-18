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

#include "msg/RA_Login_Request_Msg.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a login request message that requests
 * user id and password from the end user.
 */
TPS_PUBLIC RA_Login_Request_Msg::RA_Login_Request_Msg (int invalid_pw, int blocked)
{
    m_invalid_pw = invalid_pw;
    m_blocked = blocked;
}

/**
 * Destructs a login request message.
 */
TPS_PUBLIC RA_Login_Request_Msg::~RA_Login_Request_Msg ()
{
}

/**
 * Retrieves message type.
 */
TPS_PUBLIC RA_Msg_Type RA_Login_Request_Msg::GetType ()
{
    return MSG_LOGIN_REQUEST;
}

/**
 * Is the password invalid in the previous login
 * request.
 */
TPS_PUBLIC int RA_Login_Request_Msg::IsInvalidPassword()
{
    return m_invalid_pw;
}

/**
 * Should the client block due to the previous
 * invalid login.
 */
TPS_PUBLIC int RA_Login_Request_Msg::IsBlocked()
{
    return m_blocked;
}
