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

#ifdef __cplusplus
extern "C"
{
#endif

#include "httpd/httpd.h"
#include "httpd/http_log.h"
#include "nspr.h"

#include "modules/tps/AP_Context.h"

#define MAX_LOG_MSG_SIZE               4096

APLOG_USE_MODULE(tps);


AP_Context::AP_Context( server_rec *sv )
{
    m_sv = sv;
}


AP_Context::~AP_Context()
{
    /* no clean up */
}


void AP_Context::LogError( const char *func, int line, const char *fmt, ... )
{
    char buf[MAX_LOG_MSG_SIZE];

    va_list argp; 
    va_start( argp, fmt );
    PR_vsnprintf( buf, MAX_LOG_MSG_SIZE, fmt, argp );
    va_end( argp );

    ap_log_error( func, line, APLOG_MODULE_INDEX, APLOG_ERR, 0, m_sv, buf );
}


void AP_Context::LogInfo( const char *func, int line, const char *fmt, ... )
{
    char buf[MAX_LOG_MSG_SIZE];

    va_list argp; 
    va_start( argp, fmt );
    PR_vsnprintf( buf, MAX_LOG_MSG_SIZE, fmt, argp );
    va_end( argp );

    ap_log_error( func, line, APLOG_MODULE_INDEX, APLOG_INFO, 0, m_sv, buf );
}


void AP_Context::InitializationError( const char *func, int line )
{
    ap_log_error( func, line, APLOG_MODULE_INDEX, APLOG_INFO, 0, m_sv,
                  "The nss module must be initialized "
                  "prior to calling the tps module." );
}

#ifdef __cplusplus
}
#endif

