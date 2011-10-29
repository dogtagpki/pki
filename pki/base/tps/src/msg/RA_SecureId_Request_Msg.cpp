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

#include "msg/RA_SecureId_Request_Msg.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a Secure ID request message for requesting
 * Secure ID input from the end user.
 */
TPS_PUBLIC RA_SecureId_Request_Msg::RA_SecureId_Request_Msg (int pin_required, int next_value)
{
    m_pin_required = pin_required;
    m_next_value = next_value;
}

/**
 * Destructs a Secure ID request.
 */
TPS_PUBLIC RA_SecureId_Request_Msg::~RA_SecureId_Request_Msg ()
{
}

/**
 * Retrieves the message type.
 */
TPS_PUBLIC RA_Msg_Type RA_SecureId_Request_Msg::GetType ()
{
    return MSG_SECUREID_REQUEST;
}

/**
 * Is PIN required?
 */
TPS_PUBLIC int RA_SecureId_Request_Msg::IsPinRequired()
{
    return m_pin_required;
}

/**
 * Is next value required?
 */
TPS_PUBLIC int RA_SecureId_Request_Msg::IsNextValue()
{
    return m_next_value;
}
