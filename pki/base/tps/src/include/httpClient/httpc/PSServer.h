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

#ifndef __PS_SERVER_H__
#define __PS_SERVER_H__

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

#include <stdio.h>
#include <time.h>
#include <ctype.h>

#include "nspr.h"
#include "plhash.h"
#include "plstr.h"

#include "ldap.h"

#define PRESENCESERVER_DLL
#include "httpClient/httpc/PSServerLib.h"
#include "httpClient/httpc/PresenceServer.h"

#include "httpClient/httpc/Defines.h"
#include "httpClient/httpc/PSError.h"
#include "httpClient/httpc/PSHelper.h"
#include "httpClient/httpc/PSConfig.h"
#include "httpClient/httpc/PSConfigReader.h"
#include "httpClient/httpc/PSConfigManager.h"
#include "httpClient/httpc/Cache.h"
#include "httpClient/httpc/StringList.h"
#include "httpClient/httpc/StringUtil.h"
#include "httpClient/httpc/ScheduledTask.h"
#include "httpClient/httpc/PSCrypt.h"

#include "httpClient/httpc/PSListener.h"
#include "httpClient/httpc/PSBuddy.h"
#include "httpClient/httpc/PSBuddyService.h"
#include "httpClient/httpc/PSBuddyListener.h"
#include "httpClient/httpc/PSServerListener.h"
#include "httpClient/httpc/PSServiceListener.h"
#include "httpClient/httpc/PSPluginManager.h"
#include "httpClient/httpc/PSServiceManager.h"
#include "httpClient/httpc/PSPlugin.h"
#include "httpClient/httpc/PSUser.h"
#include "httpClient/httpc/PSDataSourceListener.h"
#include "httpClient/httpc/PSDataSourceManager.h"
#include "httpClient/httpc/PSGroup.h"
#include "httpClient/httpc/PSGroupCache.h"
#include "httpClient/httpc/PSBuddyCache.h"
#include "httpClient/httpc/PSBuddyList.h"
#include "httpClient/httpc/PresenceManager.h"
#include "httpClient/httpc/PSServerManager.h"

#include "httpClient/httpc/ErrorLogger.h"
#include "httpClient/httpc/DebugLogger.h"
#include "httpClient/httpc/ScheduledTask.h"
#include "httpClient/httpc/LogRotationTask.h"
#include "httpClient/httpc/TaskList.h"
#include "httpClient/httpc/Scheduler.h"

#endif // __PS_SERVER_H__


