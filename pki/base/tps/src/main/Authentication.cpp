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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "main/RA_Session.h"
#include "main/Login.h"
#include "main/SecureId.h"
#include "main/Util.h"
#include "main/Memory.h"
#include "authentication/Authentication.h"
#include "authentication/AuthParams.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a base authentication
 */
TPS_PUBLIC Authentication::Authentication ()
{
}

/**
 * Destructs processor.
 */
TPS_PUBLIC Authentication::~Authentication ()
{
}

void Authentication::Initialize(int index)
{
}

int Authentication::Authenticate(AuthParams *params)
{
    return -1;
}

int Authentication::GetNumOfRetries() {
    return m_retries;
}

const char *Authentication::GetTitle(char *locale)
{
    return NULL;
}
                                                                                
const char *Authentication::GetDescription(char *locale)
{
    return NULL;
}

int Authentication::GetNumOfParamNames()
{
    return 0;
}

char *Authentication::GetParamID(int index)
{
    return NULL;
}

const char *Authentication::GetParamName(int index, char *locale)
{
    return NULL;
}

char *Authentication::GetParamType(int index)
{
    return NULL;
}

const char *Authentication::GetParamDescription(int index, char *locale)
{
    return NULL;
}

char *Authentication::GetParamOption(int index)
{
    return NULL;
}

