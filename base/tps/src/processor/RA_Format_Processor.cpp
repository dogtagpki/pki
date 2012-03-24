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

#include <string.h>

#include "main/RA_Session.h"
#include "main/RA_Msg.h"
#include "main/Buffer.h"
#include "main/Util.h"
#include "engine/RA.h"
#include "channel/Secure_Channel.h"
#include "msg/RA_SecureId_Request_Msg.h"
#include "msg/RA_SecureId_Response_Msg.h"
#include "msg/RA_New_Pin_Request_Msg.h"
#include "msg/RA_New_Pin_Response_Msg.h"
#include "processor/RA_Processor.h"
#include "processor/RA_Format_Processor.h"
#include "cms/CertEnroll.h"
#include "httpClient/httpc/response.h"
#include "main/Memory.h"
#include "tus/tus_db.h"
#include "ldap.h"

#define OP_PREFIX "op.format"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a processor for handling upgrade operation.
 */
TPS_PUBLIC RA_Format_Processor::RA_Format_Processor ()
{
}

/**
 * Destructs upgrade processor.
 */
TPS_PUBLIC RA_Format_Processor::~RA_Format_Processor ()
{
}

/**
 * Processes the current session.
 */
TPS_PUBLIC RA_Status RA_Format_Processor::Process(RA_Session *session, NameValueSet *extensions)
{
    bool skip_auth = false;
    return Format(session,extensions,skip_auth);
}
