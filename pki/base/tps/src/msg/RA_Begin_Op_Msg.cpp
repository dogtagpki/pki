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

#include "msg/RA_Begin_Op_Msg.h"
#include "main/Memory.h"
#include "main/NameValueSet.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a begin op message. Each operation
 * transaction (i.e. enrollment, reset pin) 
 * starts with a Begin Op message.
 */
TPS_PUBLIC RA_Begin_Op_Msg::RA_Begin_Op_Msg (RA_Op_Type op, NameValueSet *exts)
{
    m_op = op;
    m_exts = exts;
}

/**
 * Destructs a begin op message.
 */
TPS_PUBLIC RA_Begin_Op_Msg::~RA_Begin_Op_Msg ()
{
    if( m_exts != NULL ) {
        delete m_exts;
        m_exts = NULL;
    }
}

/**
 * Retrieves message type.
 */
TPS_PUBLIC RA_Msg_Type RA_Begin_Op_Msg::GetType ()
{
    return MSG_BEGIN_OP;
}

TPS_PUBLIC NameValueSet *RA_Begin_Op_Msg::GetExtensions()
{
    return m_exts;
}

/**
 * Retrieves operation type.
 */
TPS_PUBLIC RA_Op_Type RA_Begin_Op_Msg::GetOpType()
{
    return m_op;
}
