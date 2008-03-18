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

#include "main/RA_Msg.h"
#include "main/Memory.h"

/**
 * Constructs a message that represents the
 * message between RA and the netkey client.
 */
RA_Msg::RA_Msg ()
{
}

/**
 * Destructs the message.
 */
RA_Msg::~RA_Msg ()
{
}

/**
 * Retrieves the message type.
 */
RA_Msg_Type RA_Msg::GetType ()
{
	return MSG_UNDEFINED;
}
