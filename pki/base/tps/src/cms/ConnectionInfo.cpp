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
#include "plstr.h"
#include "cms/ConnectionInfo.h"
#include "engine/RA.h"
#include "httpClient/httpc/engine.h"
#include "main/Util.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a base processor.
 */
TPS_PUBLIC ConnectionInfo::ConnectionInfo ()
{
    for( int i = 0; i < HOST_PORT_MEMBERS; i++ ) {
        m_hostPortList[i] = NULL;
    }
}

/**
 * Destructs processor.
 */
TPS_PUBLIC ConnectionInfo::~ConnectionInfo()
{
    for (int i=0; i<m_len; i++) {
        if( m_hostPortList[i] != NULL ) {
            PL_strfree( m_hostPortList[i] );
            m_hostPortList[i] = NULL;
        }
    }
}

TPS_PUBLIC void ConnectionInfo::BuildFailoverList(const char *str) {
    char *lasts = NULL;
    char *tok = PL_strtok_r((char *)str, " ", &lasts);
    m_len = 0;
    while (tok != NULL) {
        m_hostPortList[m_len] = PL_strdup(tok);
        tok = PL_strtok_r(NULL, " ", &lasts);
        m_len++;
    }
}

TPS_PUBLIC int ConnectionInfo::GetHostPortListLen() {
    return m_len;
}

TPS_PUBLIC char **ConnectionInfo::GetHostPortList() { 
    return m_hostPortList;
}

