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

#include "main/Base.h"
#include "main/Buffer.h"
#include "main/Util.h"
#include "engine/RA.h"
#include "channel/Channel.h"
#include "msg/RA_Token_PDU_Request_Msg.h"
#include "msg/RA_Token_PDU_Response_Msg.h"
#include "apdu/Lifecycle_APDU.h"
#include "apdu/Initialize_Update_APDU.h"
#include "apdu/External_Authenticate_APDU.h"
#include "apdu/Create_Object_APDU.h"
#include "apdu/Set_Pin_APDU.h"
#include "apdu/Read_Buffer_APDU.h"
#include "apdu/Write_Object_APDU.h"
#include "apdu/Generate_Key_APDU.h"
#include "apdu/Put_Key_APDU.h"
#include "apdu/Delete_File_APDU.h"
#include "apdu/Load_File_APDU.h"
#include "apdu/Install_Applet_APDU.h"
#include "apdu/Install_Load_APDU.h"
#include "apdu/Format_Muscle_Applet_APDU.h"
#include "apdu/Create_Pin_APDU.h"
#include "apdu/List_Pins_APDU.h"
#include "apdu/APDU_Response.h"
#include "main/Memory.h"

/**
 * Constructs a secure channel between the RA and the 
 * token key directly.
 */
Channel::Channel()
{
} /* Channel */

/**
 * Destroys this secure channel.
 */
Channel::~Channel ()
{
} /* ~Channel */

/**
 * Closes secure channel.
 */
int Channel::Close()
{
    /* currently do not have anything to terminate here */
    return 1;
}
