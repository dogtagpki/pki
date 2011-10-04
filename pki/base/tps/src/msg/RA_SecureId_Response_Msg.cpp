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
#include "msg/RA_SecureId_Response_Msg.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a Secure ID response.
 */
TPS_PUBLIC RA_SecureId_Response_Msg::RA_SecureId_Response_Msg (char *value, char *pin)
{
    if (value == NULL) 
        m_value = NULL;
    else 
        m_value = PL_strdup(value);
    if (pin == NULL)
        m_pin = NULL;
    else
        m_pin = PL_strdup(pin);
}

/**
 * Destructs a Secure ID response.
 */
TPS_PUBLIC RA_SecureId_Response_Msg::~RA_SecureId_Response_Msg ()
{
    if( m_value != NULL ) {
        PL_strfree( m_value );
        m_value = NULL;
    }
    if( m_pin != NULL ) {
        PL_strfree( m_pin );
        m_pin = NULL;
    }
}

/**
 * Retrieves the message type.
 */
TPS_PUBLIC RA_Msg_Type RA_SecureId_Response_Msg::GetType ()
{
    return MSG_SECUREID_RESPONSE;
}

/**
 * Retrieves the value.
 */
TPS_PUBLIC char *RA_SecureId_Response_Msg::GetValue()
{
    return m_value;
}

/**
 * Retrieves the PIN.
 */
TPS_PUBLIC char *RA_SecureId_Response_Msg::GetPIN()
{
    return m_pin;
}
