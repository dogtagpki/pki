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

#ifndef __DEFINES_H__
#define __DEFINES_H__

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
 * Defines.h	1.000 04/30/2002
 * 
 * This file contains global constants for the Presence Server
 *
 * @author  Rob Weltman
 * @author  Surendra Rajam
 * @version 1.000, 04/30/2002
 */

// ??? SSR till we have server logging functionality
#ifdef _DEBUG
#define PS_LOG_LEVEL PS_LOG_LEVEL_DEBUG
#else
#define PS_LOG_LEVEL PS_LOG_LEVEL_WARN
#endif

#define PS_SERVER_CONFIG_FILE		"psserver.conf"

// Configuration file for WASP SOAP server
#define SOAP_CONFIG_FILE            "config.xml"

#define CLIENT_DESCRIPTION          "Netscape Presence Server"
#define SERVER_VERSION              "1.0"

// Key to SoapAction field in WASP call context
#define HEADER_FIELD_SOAPACTION     "SOAP_ACTION"
// Key to status field in WASP call context
#define HEADER_STATUS               "HEADER_STATUS"

// Keys to client parameters passed through the call context

#define SERVER_URL                  "SERVER_URL"
#define CERTIFICATE_DIRECTORY       "CERTIFICATE_DIRECTORY"
#define CERTIFICATE_NICKNAME        "CERTIFICATE_NICKNAME"
#define DO_SERVER_CERT_VALIDATION   "DO_SERVER_CERT_VALIDATION"
#define CERTIFICATE_PASSWORD        "CERTIFICATE_PASSWORD"

#define STRING_ON_LINE	 "ONLINE"
#define STRING_OFF_LINE	 "OFFLINE"

#define BATCH_RESULT_SIZE				1000
#define MAX_ATTR_SIZE					   5

#define NAME_BUFFER_LENGTH				256
#define ATTR_BUFFER_LENGTH				256

// Static strings for the attributes we support
#define BUDDY_ATTRIBUTE_ON_LINE_STATUS	"onlinestatus"
#define BUDDY_ATTRIBUTE_IDLE_TIME		"idletime"
#define BUDDY_ATTRIBUTE_ON_LINE_SINCE	"onlinesince"
#define BUDDY_ATTRIBUTE_AWAY_MESSAGE	"awaymessage"
#define BUDDY_ATTRIBUTE_PROFILE			"profile"
#define BUDDY_ATTRIBUTE_CONNECTION_TYPE	"connectiontype"
#define BUDDY_ATTRIBUTE_CAPABILITIES	"capabilities"

#define PS_LOG_LEVEL_DEBUG			0
#define PS_LOG_LEVEL_WARN			1
#define PS_LOG_LEVEL_ERROR			2


// Presence Server config parameters in the bootstrap configuration file
// psserver.conf
#define INSTANCE_ID		"instanceid"
#define HOST_ID			"hostid"
#define DOMAIN_NAME		"domainname"
#define SERVER_HOST		"serverhost"
#define SERVER_PORT		"serverport"
#define BINDDN			"binddn"
#define BINDPASSWORD	"bindpassword"

// dn, cn constants
#define PS_ATTRIBUTE_DN				"dn"
#define PS_ATTRIBUTE_CN				"cn"

// nsPlugin class required attributes
#define PLUGIN_DN			"dn"
#define PLUGIN_CN			"cn"
#define PLUGIN_ID			"nspluginid"
#define PLUGIN_PATH			"nspluginpath"
#define PLUGIN_INIT_FUNC	"nsplugininitfunc"
#define PLUGIN_ENABLED		"nspluginenabled"
#define PLUGIN_VERSION		"nspluginversion"
#define PLUGIN_DESC			"nsplugindescription"

// Operations when updating server
#define PS_OPERATION_ADD		1
#define PS_OPERATION_DELETE		2
#define PS_OPERATION_REPLACE	4

// Names of LDAP attributes for the LDAP data source
#define LDAP_SOURCE_DN						"dn"
#define LDAP_SOURCE_CN						"cn"
#define LDAP_SOURCE_GROUP_NAME				"nspsgroupname"
#define LDAP_SOURCE_SERVER_ADDRESS			"nsserveraddress"
#define LDAP_SOURCE_SERVER_PORT				"nsserverport"
#define LDAP_SOURCE_BIND_DN					"nsbinddn"
#define LDAP_SOURCE_BIND_PASSWORD			"nsbindpassword"
#define LDAP_SOURCE_BASE_DN					"nsbasedn"
#define LDAP_SOURCE_SEARCH_FILTER			"nssearchfilter"
#define LDAP_SOURCE_SEARCH_SCOPE			"nssearchscope"
#define LDAP_SOURCE_IM_ID					"nsimattributetype"
#define LDAP_SOURCE_SEARCHABLE_ATTRIBUTES	"nssearchableattributes"
#define LDAP_SOURCE_ENABLE_SSL				"nsenablessl"


// Configuration attribute name for max results to return
#define SEARCH_MAX_RESULTS    "nsmaxresults"

// Max results to return if SEARCH_MAX_RESULTS is not defined
#define DEFAULT_MAX_RESULTS   1000

// Names of configuration clusters
#define CONFIG_BASE                         "ConfigBase"
#define CONFIG_AUTHORIZE                    "ConfigAuthorize"
#define CONFIG_ACCESS_LOG                   "ConfigAccessLog"
#define CONFIG_ERROR_LOG                    "ConfigErrorLog"
#define CONFIG_DEBUG_LOG                    "ConfigDebugLog"
#define CONFIG_SERVER_LOCAL					"ConfigServerLocal"

// Configuration attributes for loggers
#define LOG_ACCESS_DIR                      "nslogdir"
#define LOG_ERROR_DIR                       "nslogdir"
#define LOG_DEBUG_DIR                       "nslogdir"
#define LOG_ACCESS_BUFFER_SIZE              "nslogbuffersize"
#define LOG_ACCESS_BUFFER_TIME              "nslogbuffertime"
#define LOG_ACCESS_ROTATION_TIME            "nslogrotationtime"
#define LOG_ACCESS_ROTATION_SIZE            "nslogrotationsize"
#define LOG_ACCESS_MAX_LOGS                 "nslogmaxlogs"
#define LOG_ERROR_ROTATION_TIME             "nslogrotationtime"
#define LOG_ERROR_ROTATION_SIZE             "nslogrotationsize"
#define LOG_ERROR_MAX_LOGS                  "nslogmaxlogs"
#define LOG_DEBUG_LEVEL                     "nsloglevel"
#define LOG_DEBUG_FORMAT                    "nslogformat"

// Static constants for logging
#define LOG_ACCESS_FILENAME                 "access"
#define LOG_ERROR_FILENAME                  "error"
#define LOG_DEBUG_FILENAME                  "debug"

// Log level definitions

typedef enum {
	LOGLEVEL_OFF = 0,
	LOGLEVEL_SEVERE = 1,
	LOGLEVEL_WARNING = 2,
	LOGLEVEL_INFO = 3,
	LOGLEVEL_CONFIG = 4,
	LOGLEVEL_FINE = 5,
	LOGLEVEL_FINER = 6,
	LOGLEVEL_FINEST = 7,
	LOGLEVEL_ALL = 100
} LogLevel;

// Config params
#define CONFIG_DEFAULT_BUFFER_LEN	2048
#define BASE_CONFIG_DN              "cn=Netscape Presence Server,cn=Server Group,cn=%s,ou=%s,o=NetscapeRoot"

// COOL Service params
#define COOL_SERVICE_SERVER_HOST			"CoolServerHost"
#define COOL_SERVICE_SERVER_PORT			"CoolServerPort"
#define COOL_SERVICE_LOGIN_NAME				"CoolLoginName"
#define COOL_SERVICE_LOGIN_PSWD				"CoolLoginPswd"

#define COOL_DEFAULT_SERVER_HOST			"coolkey.fedora.redhat.com"
#define COOL_DEFAULT_SERVER_PORT			"5190"

// Key to service ID in global config
#define SERVICE_TYPE                        "service_type"

#define MODULE_IM_SERVICE					"ModuleIMService"
#define MODULE_DATA_SOURCE					"ModuleDataSource"

#define PROVIDER_BATCH_SIZE_ATTR			"nsbatchsize"
#define PROVIDER_UPDATE_INTERVAL_ATTR		"nsupdateinterval"

#define THREAD_POOL_TASK_NAME				"ThreadPoolTask"

#endif // __DEFINES_H__
