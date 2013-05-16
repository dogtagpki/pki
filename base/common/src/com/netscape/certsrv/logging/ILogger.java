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

import java.util.Properties;

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
    public static final int EV_AUDIT = 0;
    public static final String PROP_AUDIT = "transaction";

    /**
     * log class: system event.
     * System event with log level >= LL_FAILURE will also be logged in error log
     */
    public static final int EV_SYSTEM = 1;
    public static final String PROP_SYSTEM = "system";

    /**
     * log class: SignedAudit event.
     */
    public static final int EV_SIGNED_AUDIT = 2;
    public static final String PROP_SIGNED_AUDIT = "signedAudit";

    //List of defined log sources.

    /**
     * log source: used by servlet to retrieve all logs
     */
    public static final int S_ALL = 0; //used by servlet only

    /**
     * log source: identify the log entry is from KRA
     */
    public static final int S_KRA = 1;

    /**
     * log source: identify the log entry is from RA
     */
    public static final int S_RA = 2;

    /**
     * log source: identify the log entry is from CA
     */
    public static final int S_CA = 3;

    /**
     * log source: identify the log entry is from http subsystem
     */
    public static final int S_HTTP = 4;

    /**
     * log source: identify the log entry is from database subsystem
     */
    public static final int S_DB = 5;

    /**
     * log source: identify the log entry is from authentication subsystem
     */
    public static final int S_AUTHENTICATION = 6;

    /**
     * log source: identify the log entry is from admin subsystem
     */
    public static final int S_ADMIN = 7;

    /**
     * log source: identify the log entry is from ldap subsystem
     */
    public static final int S_LDAP = 8;

    /**
     * log source: identify the log entry is from request queue subsystem
     */
    public static final int S_REQQUEUE = 9;

    /**
     * log source: identify the log entry is from acl subsystem
     */
    public static final int S_ACLS = 10;

    /**
     * log source: identify the log entry is from usergrp subsystem
     */
    public static final int S_USRGRP = 11;
    public static final int S_OCSP = 12;

    /**
     * log source: identify the log entry is from authorization subsystem
     */
    public static final int S_AUTHORIZATION = 13;

    /**
     * log source: identify the log entry is from signed audit
     */
    public static final int S_SIGNED_AUDIT = 14;

    /**
     * log source: identify the log entry is from CrossCertPair subsystem
     */
    public static final int S_XCERT = 15;

    /**
     * log source: identify the log entry is from CrossCertPair subsystem
     */

    public static final int S_TKS = 16;
    public static final int S_TPS = 17;

    /**
     * log source: identify the log entry is from other subsystem
     * eg. policy, security, connector,registration
     */
    public static final int S_OTHER = 20;

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
    public void log(int evtClass, int source, String msg);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param props The resource bundle used for the detailed message.
     * @param source The source of the log event.
     * @param msg The detail message to be logged.
     */
    public void log(int evtClass, Properties props, int source, String msg);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     */
    public void log(int evtClass, int source, int level, String msg);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param props The resource bundle used for the detailed message.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     */
    public void log(int evtClass, Properties props, int source, int level, String msg);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     * @param param The parameter in the detail message.
     */
    public void log(int evtClass, int source, int level, String msg, Object param);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     * @param params The parameters in the detail message.
     */
    public void log(int evtClass, int source, int level, String msg, Object params[]);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param props The resource bundle used for the detailed message.
     * @param source The source of the log event.
     * @param msg The detail message to be logged.
     * @param param The parameters in the detail message.
     */
    public void log(int evtClass, Properties props, int source, String msg, Object param);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param props The resource bundle used for the detailed message.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     * @param param The parameter in the detail message.
     */
    public void log(int evtClass, Properties props, int source, int level, String msg,
            Object param);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param prop The resource bundle used for the detailed message.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     * @param params The parameters in the detail message.
     */
    public void log(int evtClass, Properties prop, int source, int level, String msg,
            Object params[]);

    //multiline log

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param source The source of the log event.
     * @param msg The detail message to be logged.
     * @param multiline true If the message has more than one line, otherwise false.
     */
    public void log(int evtClass, int source, String msg, boolean multiline);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param props The resource bundle used for the detailed message.
     * @param source The source of the log event.
     * @param msg The detail message to be logged.
     * @param multiline True if the message has more than one line, otherwise false.
     */
    public void log(int evtClass, Properties props, int source, String msg, boolean multiline);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     * @param multiline True if the message has more than one line, otherwise false.
     */
    public void log(int evtClass, int source, int level, String msg, boolean multiline);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param props The resource bundle used for the detailed message.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     * @param multiline True if the message has more than one line, otherwise false.
     */
    public void log(int evtClass, Properties props, int source, int level, String msg, boolean multiline);

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
    public void log(int evtClass, int source, int level, String msg, Object param, boolean multiline);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param props The resource bundle used for the detailed message.
     * @param source TTTTsource of the log event.
     * @param msg The detail message to be logged.
     * @param param The parameter in the detail message.
     * @param multiline True if the message has more than one line, otherwise false.
     */
    public void log(int evtClass, Properties props, int source, String msg, Object param, boolean multiline);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param props The resource bundle used for the detailed message.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     * @param param The parameter in the detail message.
     * @param multiline True if the message has more than one line, otherwise false.
     */
    public void log(int evtClass, Properties props, int source, int level, String msg,
            Object param, boolean multiline);

    /**
     * Logs an event to the log queue.
     *
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param prop The resource bundle used for the detailed message.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     * @param params The parameters in the detail message.
     * @param multiline True if the message has more than one line, otherwise false.
     */
    public void log(int evtClass, Properties prop, int source, int level, String msg,
            Object params[], boolean multiline);

    /*
     * Generates an ILogEvent
     * @param evtClass What kind of event it is: EV_AUDIT or EV_SYSTEM or EV_SIGNED_AUDIT.
     * @param props The resource bundle used for the detailed message.
     * @param source The source of the log event.
     * @param level The level of the log event.
     * @param msg The detail message to be logged.
     * @param params The parameters in the detail message.
     * @param multiline True if the message has more than one line, otherwise false.
     * @return ILogEvent, a log event.
     */
    public ILogEvent create(int evtClass, Properties prop, int source, int level,
            String msg, Object params[], boolean multiline);

    /**
     * Register a log event factory. Which will create the desired ILogEvents.
     */
    public void register(int evtClass, ILogEventFactory f);

    /**
     * Retrieves the associated log queue. The log queue is where issued log events
     * are collected for later processing.
     */
    public ILogQueue getLogQueue();

}
