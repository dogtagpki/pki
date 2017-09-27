// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.logging;

/**
 * An interface represents a logger for certificate server. This object is used to
 * issue log messages for the various types of logging event types. A log message results
 * in a ILogEvent being created. This event is then placed on a ILogQueue to be ultimately
 * written to the destination log file. This object also maintains a collection of ILogFactory objects
 * which are used to create the supported types of ILogEvents. CMS comes out of the box with three event
 * types: "signedAudit", "system", and "audit".
 *
 * @version $Revision$, $Date$
 */
public interface ILogger {

    //List of defined log classes.
    /**
     * log class: audit event.
     */
    public static final LogCategory EV_AUDIT = LogCategory.TRANSACTION;
    public static final String PROP_AUDIT = "transaction";

    /**
     * log class: system event.
     * System event with log level >= LL_FAILURE will also be logged in error log
     */
    public static final LogCategory EV_SYSTEM = LogCategory.SYSTEM;
    public static final String PROP_SYSTEM = "system";

    /**
     * log class: SignedAudit event.
     */
    public static final LogCategory EV_SIGNED_AUDIT = LogCategory.SIGNED_AUDIT;
    public static final String PROP_SIGNED_AUDIT = "signedAudit";

    //List of defined log sources.

    /**
     * log source: used by servlet to retrieve all logs
     */
    public static final LogSource S_ALL = LogSource.ALL; //used by servlet only

    /**
     * log source: identify the log entry is from KRA
     */
    public static final LogSource S_KRA = LogSource.KRA;

    /**
     * log source: identify the log entry is from RA
     */
    public static final LogSource S_RA = LogSource.RA;

    /**
     * log source: identify the log entry is from CA
     */
    public static final LogSource S_CA = LogSource.CA;

    /**
     * log source: identify the log entry is from http subsystem
     */
    public static final LogSource S_HTTP = LogSource.HTTP;

    /**
     * log source: identify the log entry is from database subsystem
     */
    public static final LogSource S_DB = LogSource.DB;

    /**
     * log source: identify the log entry is from authentication subsystem
     */
    public static final LogSource S_AUTHENTICATION = LogSource.AUTHENTICATION;

    /**
     * log source: identify the log entry is from admin subsystem
     */
    public static final LogSource S_ADMIN = LogSource.ADMIN;

    /**
     * log source: identify the log entry is from ldap subsystem
     */
    public static final LogSource S_LDAP = LogSource.LDAP;

    /**
     * log source: identify the log entry is from request queue subsystem
     */
    public static final LogSource S_REQQUEUE = LogSource.REQQUEUE;

    /**
     * log source: identify the log entry is from acl subsystem
     */
    public static final LogSource S_ACLS = LogSource.ACLS;

    /**
     * log source: identify the log entry is from usergrp subsystem
     */
    public static final LogSource S_USRGRP = LogSource.USRGRP;
    public static final LogSource S_OCSP = LogSource.OCSP;

    /**
     * log source: identify the log entry is from authorization subsystem
     */
    public static final LogSource S_AUTHORIZATION = LogSource.AUTHORIZATION;

    /**
     * log source: identify the log entry is from signed audit
     */
    public static final LogSource S_SIGNED_AUDIT = LogSource.SIGNED_AUDIT;

    /**
     * log source: identify the log entry is from CrossCertPair subsystem
     */
    public static final LogSource S_XCERT = LogSource.XCERT;

    /**
     * log source: identify the log entry is from CrossCertPair subsystem
     */

    public static final LogSource S_TKS = LogSource.TKS;
    public static final LogSource S_TPS = LogSource.TPS;

    /**
     * log source: identify the log entry is from other subsystem
     * eg. policy, security, connector,registration
     */
    public static final LogSource S_OTHER = LogSource.OTHER;

    // List of defined log levels.
    /**
     * log level: used by servlet to retrieve all level logs
     */
    public static final int LL_ALL = -1; //used by servlet only
    public static final String LL_ALL_STRING = "All"; //used by servlet only

    /**
     * log level: indicate this log entry is debug info
     */

    /**
     * Debug level is depreciated since CMS6.1. Please use
     * CMS.debug() to output messages to debugging file.
     */
    public static final int LL_DEBUG = 0; // depreciated
    public static final String LL_DEBUG_STRING = "Debug";

    /**
     * log level: indicate this log entry is for info note
     */
    public static final int LL_INFO = 1;
    public static final String LL_INFO_STRING = "Information";

    /**
     * log level: indicate this log entry is warning info
     */
    public static final int LL_WARN = 2;
    public static final String LL_WARN_STRING = "Warning";

    /**
     * log level: indicate this log entry is fail/error info
     */
    public static final int LL_FAILURE = 3;
    public static final String LL_FAILURE_STRING = "Failure";

    /**
     * log level: indicate this log entry is about misconfiguration
     */
    public static final int LL_MISCONF = 4;
    public static final String LL_MISCONF_STRING = "Misconfiguration";

    /**
     * log level: indicate this log entry is catastrphe info
     */
    public static final int LL_CATASTRPHE = 5;
    public static final String LL_CATASTRPHE_STRING = "Catastrophe";

    /**
     * log level: indicate this log entry is security info
     */
    public static final int LL_SECURITY = 6;
    public static final String LL_SECURITY_STRING = "Security";

    /**
     * "SubjectID" for system-initiated events logged
     * in signed audit log messages
     */
    public static final String SYSTEM_UID = "$System$";

    /**
     * A constant string value used to denote a single "unknown" identity
     * in signed audit log messages
     */
    public static final String UNIDENTIFIED = "$Unidentified$";

    /**
     * A constant string value used to denote a single "non-role" identity
     * in signed audit log messages
     */
    public static final String NONROLEUSER = "$NonRoleUser$";

    /**
     * "Outcome" for events logged in signed audit log messages
     */
    public static final String SUCCESS = "Success";
    public static final String FAILURE = "Failure";

    /**
     * A constant string value used to denote a "non-applicable"
     * data value in signed audit log messages
     */
    public final static String SIGNED_AUDIT_NON_APPLICABLE = "N/A";

    /**
     * A constant string value used to denote an "empty", or "null",
     * data value in signed audit log messages
     */
    public final static String SIGNED_AUDIT_EMPTY_VALUE = "<null>";

    /**
     * Constant string values associated with the type of certificate
     * processing stored in the "InfoName" field in certain signed
     * audit log messages
     */
    public final static String SIGNED_AUDIT_ACCEPTANCE = "certificate";
    public final static String SIGNED_AUDIT_CANCELLATION = "cancelReason";
    public final static String SIGNED_AUDIT_REJECTION = "rejectReason";

    // List of all NT event type
    /**
     * NT event type: correspond to log level LL_DEBUG or LL_INFO
     */
    public static final int NT_INFO = 4;

    /**
     * NT event type: correspond to log level LL_WARNING
     */
    public static final int NT_WARN = 2;

    /**
     * NT event type: correspont to log level LL_FAILURE and above
     */
    public static final int NT_ERROR = 1;

    // List of defined log multiline attribute.
    /**
     * indicate the log message has more than one line
     */
    public static final boolean L_MULTILINE = true;

    /**
     * indicate the log message has one line
     */
    public static final boolean L_SINGLELINE = false;

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param source The source of the log event.
     * @param msg The detail message to be logged.
     */
    public void log(LogCategory evtClass, LogSource source, String msg);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     */
    public void log(LogCategory evtClass, LogSource source, int level, String msg);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     * @param param The parameter in the detail message.
     */
    public void log(LogCategory evtClass, LogSource source, int level, String msg, Object param);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     * @param params The parameters in the detail message.
     */
    public void log(LogCategory evtClass, LogSource source, int level, String msg, Object params[]);

    //multiline log

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param source The source of the log event.
     * @param msg The detail message to be logged.
     * @param multiline true If the message has more than one line, otherwise false.
     */
    public void log(LogCategory evtClass, LogSource source, String msg, boolean multiline);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     * @param multiline True if the message has more than one line, otherwise false.
     */
    public void log(LogCategory evtClass, LogSource source, int level, String msg, boolean multiline);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     * @param param The parameter in the detail message.
     * @param multiline True if the message has more than one line, otherwise false.
     */
    public void log(LogCategory evtClass, LogSource source, int level, String msg, Object param, boolean multiline);

    /*
     * Generates an ILogEvent
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     * @param params The parameters in the detail message.
     * @param multiline True if the message has more than one line, otherwise false.
     * @return ILogEvent, a log event.
     */
    public ILogEvent create(LogCategory evtClass, LogSource source, int level,
            String msg, Object params[], boolean multiline);

    /**
     * Retrieves the associated log queue. The log queue is where issued log events
     * are collected for later processing.
     */
    public ILogQueue getLogQueue();
}
