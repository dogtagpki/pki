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
#include "processor/RA_Processor.h"
#include "processor/RA_Renew_Processor.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a renew processor.
 */
TPS_PUBLIC RA_Renew_Processor::RA_Renew_Processor()
{
}

/**
 * Destructs a renew processor.
 */
TPS_PUBLIC RA_Renew_Processor::~RA_Renew_Processor()
{
}

/**
 * Processes the current session.
 */
TPS_PUBLIC RA_Status RA_Renew_Processor::Process(RA_Session *session, NameValueSet *extensions)
{
    RA::Debug("RA_Renew_Processor::Process",
        "RA_Renew_Processor::Process");

    return STATUS_NO_ERROR;
}
