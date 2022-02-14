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

#include "plstr.h"
#include "msg/RA_Login_Response_Msg.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a login response message.
 */
TPS_PUBLIC RA_Login_Response_Msg::RA_Login_Response_Msg (char *uid, char *password)
{
    if (uid == NULL)
        m_uid = NULL;
    else
        m_uid = PL_strdup(uid);
    if (password == NULL)
        m_password = NULL;
    else
        m_password = PL_strdup(password);
}

/**
 * Destructs a login response message.
 */
TPS_PUBLIC RA_Login_Response_Msg::~RA_Login_Response_Msg ()
{
    if( m_uid != NULL ) {
        PL_strfree( m_uid );
        m_uid = NULL;
    }
    if( m_password != NULL ) {
        PL_strfree( m_password );
        m_password = NULL;
    }
}

/**
 * Retrieves message type.
 */
TPS_PUBLIC RA_Msg_Type RA_Login_Response_Msg::GetType ()
{
    return MSG_LOGIN_RESPONSE;
}

/**
 * Retrieves null-pointer terminated 
 * user ID given by the end user.
 */
TPS_PUBLIC char *RA_Login_Response_Msg::GetUID()
{
    return m_uid;
}

/**
 * Retrieves null-pointer terminated password 
 * given by the end user.
 */
TPS_PUBLIC char *RA_Login_Response_Msg::GetPassword()
{
    return m_password;
}
