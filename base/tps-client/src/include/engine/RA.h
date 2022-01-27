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

#ifndef RA_H
#define RA_H

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

#include "pk11func.h"
#include "main/Base.h"
#include "main/Buffer.h"
#include "apdu/APDU.h"
#include "main/RA_Context.h"
#include "channel/Secure_Channel.h"

/*
 *
 * LL_PER_SERVER = 4        these messages will occur only once during the
 *                          entire invocation of the server, e.g. at startup
 *                          or shutdown time., reading the conf parameters.
 *                          Perhaps other infrequent events relating to
 *                          failing over of CA, TKS, too
 *
 * LL_PER_CONNECTION = 6    these messages happen once per connection - most
 *                          of the log events will be at this level
 *
 * LL_PER_PDU = 8           these messages relate to PDU processing. If you
 *                          have something that is done for every PDU, such
 *                          as applying the MAC, it should be logged at this
 *                          level
 *
 * LL_ALL_DATA_IN_PDU = 9   dump all the data in the PDU - a more chatty
 *                          version of the above
 */
enum RA_Log_Level {
	LL_PER_SERVER = 4,
	LL_PER_CONNECTION = 6,
	LL_PER_PDU = 8,
	LL_ALL_DATA_IN_PDU = 9
};

enum RA_Algs {
        ALG_RSA = 1,
        ALG_RSA_CRT = 2,
        ALG_DSA = 3,
        ALG_EC_F2M = 4,
        ALG_EC_FP = 5
};

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

#define TRANSPORT_KEY_NAME "sharedSecret"

typedef char NSSUTF8;

class RA
{
  public:
	  RA();
	  ~RA();
  public:
          static PRThread *m_flush_thread;
          static size_t m_bytes_unflushed;
          static size_t m_buffer_size;
          static int m_flush_interval;
          static RA_Context *m_ctx;
};

#endif /* RA_H */
