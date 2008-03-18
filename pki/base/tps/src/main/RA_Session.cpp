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

#include "engine/RA.h"
#include "main/RA_Msg.h"
#include "main/RA_Session.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a session that represents the
 * connection between RA and the netkey client.
 */
TPS_PUBLIC RA_Session::RA_Session ()
{
}

/**
 * Destructs the session.
 */
TPS_PUBLIC RA_Session::~RA_Session ()
{
}

char *RA_Session::GetRemoteIP()
{
	return NULL;
}

RA_pblock *RA_Session::create_pblock( char *data )
{
    // Since this method is virtual,
    // report an error if no subclass method has been defined.
    RA::Error( "RA_pblock::find_val",
               "No subclass method has been defined for this virtual method!" );
	return NULL;
}

/**
 * Reads a message that is sent by 
 * the client.
 */
RA_Msg *RA_Session::ReadMsg()
{
	return NULL;
}

/**
 * Sends a message to the client.
 */
void RA_Session::WriteMsg(RA_Msg *msg)
{
}
