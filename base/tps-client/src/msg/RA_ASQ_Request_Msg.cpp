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
#include "main/Base.h"
#include "msg/RA_ASQ_Request_Msg.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs A Security Question (ASQ) request message.
 */
TPS_PUBLIC RA_ASQ_Request_Msg::RA_ASQ_Request_Msg (char *question)
{
    if (question == NULL)
        m_question = NULL; 
    else 
        m_question = PL_strdup(question);
}


/**
 * Destructs a ASQ request message.
 */
TPS_PUBLIC RA_ASQ_Request_Msg::~RA_ASQ_Request_Msg ()
{
    if( m_question != NULL ) { 
        PL_strfree( m_question );
        m_question = NULL;
    }
}

/**
 * Retrieves the message type.
 */
TPS_PUBLIC RA_Msg_Type RA_ASQ_Request_Msg::GetType ()
{
    return MSG_ASQ_REQUEST;
}

/**
 * Retrieves the security question for
 * the end user. 
 */
TPS_PUBLIC char *RA_ASQ_Request_Msg::GetQuestion()
{
    return m_question;
}
