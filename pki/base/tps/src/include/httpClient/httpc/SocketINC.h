/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 */
/** BEGIN COPYRIGHT BLOCK
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
 * END COPYRIGHT BLOCK **/

#ifndef _SOCKET_INC_H_
#define _SOCKET_INC_H_

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

/**
 * SocketINC.h	1.000 06/12/2002
 * 
 * Public header file for Socket / Connection module
 *
 * @author  Surendra Rajam
 * @version 1.000, 06/12/2002
 */

/**************************************************
 * Imported header files 
 **************************************************/
#include <time.h>
#include <string.h>

#include "nspr.h"
#include "plhash.h"
#include "plstr.h"
#include "private/pprio.h"

#include "pk11func.h"
#include "secitem.h"
#include "ssl.h"
#include "certt.h"
#include "nss.h"
#include "secrng.h"
#include "secder.h"
#include "key.h"
#include "sslproto.h"

#include "httpClient/httpc/Defines.h"	// ??? SSR should be spilt into respective modules
#include "httpClient/httpc/Pool.h"
#include "httpClient/httpc/DebugLogger.h"
#include "httpClient/httpc/ErrorLogger.h"
#include "httpClient/httpc/CERTUtil.h"
#include "httpClient/httpc/PSPRUtil.h"

/**************************************************
 * Socket / Connection module header files 
 **************************************************/
#include "httpClient/httpc/Socket.h"
#include "httpClient/httpc/ServerSocket.h"
#include "httpClient/httpc/SSLSocket.h"
#include "httpClient/httpc/SSLServerSocket.h"
#include "httpClient/httpc/Connection.h"
#include "httpClient/httpc/ConnectionListener.h"
#include "httpClient/httpc/ServerConnection.h"


/*************************************************
 * Error codes used by this module
 *************************************************/
// Socket errors
typedef enum {
	SOCKET_ERROR_CREATE_SOCKET			= -2001,
	SOCKET_ERROR_SET_OPTION				= -2002,
	SOCKET_ERROR_BIND					= -2003,
	SOCKET_ERROR_LISTEN					= -2004,
	SOCKET_ERROR_CONNECTION_CLOSED		= -2005,
	SOCKET_ERROR_READ					= -2006,
	SOCKET_ERROR_WRITE					= -2007,
	SOCKET_ERROR_ACCEPT_THREAD			= -2008,
	SOCKET_ERROR_ALREADY_REGISTERED		= -2009,
	SOCKET_ERROR_ALREADY_LISTENING		= -2010,
	SOCKET_ERROR_POLL_THREAD			= -2011,
	SOCKET_ERROR_NO_LISTENER			= -2012,
	SOCKET_ERROR_POLL					= -2013,
	SOCKET_ERROR_POLL_TIMED_OUT			= -2014,
	SOCKET_ERROR_ALREADY_CONNECTED		= -2015,
	SOCKET_ERROR_INITIALIZATION_FAILED	= -2016
} SocketError;

typedef enum {
	SSL_ERROR_SERVER_CERT				= -2016,
	SSL_ERROR_SERVER_PRIVATE_KEY		= -2017,
	SSL_ERROR_IMPORT_FD					= -2018,
	SSL_ERROR_OPTION_SECURITY			= -2019,
	SSL_ERROR_OPTION_SERVER_HANDSHAKE	= -2020,
	SSL_ERROR_OPTION_REQUEST_CERTIFCATE	= -2021,
	SSL_ERROR_OPTION_REQUIRE_CERTIFCATE	= -2022,
	SSL_ERROR_CALLBACK_AUTH_CERTIFICATE	= -2023,
	SSL_ERROR_CALLBACK_BAD_CERT_HANDLER	= -2024,
	SSL_ERROR_CALLBACK_HAND_SHAKE		= -2025,
	SSL_ERROR_CALLBACK_PASSWORD_ARG		= -2026,
	SSL_ERROR_CONFIG_SECURE_SERVER		= -2027,
	SSL_ERROR_RESET_HAND_SHAKE			= -2028,
	SSL_ERROR_OPTION_ENABLE_FDX			= -2029
} SslError;

/**************************************************
 * Defines used by this module
 **************************************************/
#define SOCKET_DEFAULT_HOST_NAME			"localhost"
#define SOCKET_DEFAULT_READ_TIME_OUT		1000UL			// 1 sec
#define SOCKET_DEFAULT_WRITE_TIME_OUT		0xffffffffUL	// infinte
#define	SOCKET_DEFAULT_READ_BUFFER_SIZE		4096			// 4k
#define	SOCKET_DEFAULT_WRITE_BUFFER_SIZE	4096			// 4k
#define SOCKET_DEFAULT_POLL_TIMEOUT			1000UL			// 1 sec
#define SOCKET_DEFAULT_BACKLOG				50				// pending conns
#define SOCKET_DEFAULT_POOL_SIZE			100				// conn pool size

typedef enum {
	SOCKET_ERROR_SEVERE	 = 1,
	SOCKET_ERROR_WARNING = 2,
	SOCKET_ERROR_INFO	 = 3
} SocketErrorLevel;


typedef enum {
	REQUEST_CERT_NONE = 0,
	REQUIRE_CERT_NONE = 1,
	REQUEST_CERT_ONCE = 2,
	REQUIRE_CERT_ONCE = 3,
	REQUEST_CERT_ALL  = 4,
	REQUIRE_CERT_ALL  = 5
} RequireCert;

#endif // _SOCKET_INC_H_





