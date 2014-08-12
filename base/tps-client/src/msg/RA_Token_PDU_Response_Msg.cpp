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

#include "apdu/APDU_Response.h"
#include "msg/RA_Token_PDU_Response_Msg.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a Token PDU response.
 */
TPS_PUBLIC RA_Token_PDU_Response_Msg::RA_Token_PDU_Response_Msg (APDU_Response *response)
{
    m_response = response;
}

/**
 * Destructs a Token PDU response.
 */
TPS_PUBLIC RA_Token_PDU_Response_Msg::~RA_Token_PDU_Response_Msg ()
{
    if( m_response != NULL ) {
        delete m_response;
        m_response = NULL;
    }
}

/**
 * Retrieves the message type. 
 */
TPS_PUBLIC RA_Msg_Type RA_Token_PDU_Response_Msg::GetType ()
{
    return MSG_TOKEN_PDU_RESPONSE;
}

/**
 * Retrieves the response from the token.
 * This response does not follow the standard
 * APDU format. It is just a sequence of data
 * with 2 bytes, at the end, that indicates 
 * the status.
 */
TPS_PUBLIC APDU_Response *RA_Token_PDU_Response_Msg::GetResponse()
{
    return m_response;
}
