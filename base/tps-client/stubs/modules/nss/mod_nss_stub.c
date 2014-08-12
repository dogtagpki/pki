/* --- BEGIN COPYRIGHT BLOCK ---
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA 
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */

#ifdef XP_WIN32
#define MOD_NSS_STUB_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define MOD_NSS_STUB_PUBLIC
#endif /* !XP_WIN32 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef XP_WIN32
#include <unistd.h>  /* sleep */
#else /* XP_WIN32 */
#include <windows.h>
#endif /* XP_WIN32 */

#include "httpd/httpd.h"
#include "httpd/http_config.h"
#include "httpd/http_log.h"
#include "httpd/http_protocol.h"
#include "httpd/http_main.h"
#include "httpd/apr_strings.h"

MOD_NSS_STUB_PUBLIC char *nss_var_lookup( apr_pool_t *p, server_rec *s,
                                          conn_rec *c, request_rec *r,
                                          char *var )
{
	return NULL;
}

