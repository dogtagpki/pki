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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmscore.logging;

import java.util.Map;

import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogEvent;
import com.netscape.certsrv.logging.SignedAuditEvent;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;

/**
 * @author Endi S. Dewata
 */
public class Auditor {

    public final static String SIGNED_AUDIT_SCOPE = "Scope";
    public final static String SIGNED_AUDIT_OPERATION = "Operation";
    public final static String SIGNED_AUDIT_RESOURCE = "Resource";
    public final static String SIGNED_AUDIT_EMPTY_NAME_VALUE_PAIR = "Unknown";

    protected Logger signedAuditLogger;

    public Auditor() {
    }

    public void init() {
        signedAuditLogger = new SignedAuditLogger();
    }

    /**
     * Get signed audit log subject ID
     *
     * This method is called to obtain the "SubjectID" for
     * a signed audit log message.
     *
     * @return id string containing the signed audit log message SubjectID
     */
    public String getSubjectID() {

        SessionContext context = SessionContext.getExistingContext();
        if (context == null) return ILogger.UNIDENTIFIED;

        // Initialize subject ID
        String subjectID = (String)context.get(SessionContext.USER_ID);
        if (subjectID == null) return ILogger.NONROLEUSER;

        return subjectID.trim();
    }

    /**
     * Get signed audit parameters as a string.
     *
     * This method is called to convert parameters into a
     * string of name;;value pairs separated by a '+'
     * if more than one name;;value pair exists.
     *
     * @return a delimited string of one or more delimited name/value pairs
     */
    public String getParamString(String scope, String type, String id, Map<String, String> params) {

        StringBuilder parameters = new StringBuilder();

        // always identify the scope of the request
        if (scope != null) {
            parameters.append(SIGNED_AUDIT_SCOPE
                    + SignedAuditEvent.NAME_VALUE_DELIMITER
                    + scope);
        } else {
            parameters.append(SIGNED_AUDIT_EMPTY_NAME_VALUE_PAIR);
        }

        // identify the operation type of the request
        if (type != null) {
            parameters.append(SignedAuditEvent.NAME_VALUE_PAIRS_DELIMITER);

            parameters.append(SIGNED_AUDIT_OPERATION
                    + SignedAuditEvent.NAME_VALUE_DELIMITER
                    + type);
        }

        // identify the resource type of the request
        if (id != null) {
            parameters.append(SignedAuditEvent.NAME_VALUE_PAIRS_DELIMITER);

            parameters.append(SIGNED_AUDIT_RESOURCE
                    + SignedAuditEvent.NAME_VALUE_DELIMITER
                    + id);
        }
        return getParamString(parameters, params);
    }

    /**
     * Get signed audit parameters as a string.
     *
     * This method is called to convert parameters into a
     * string of name;;value pairs separated by a '+'
     * if more than one name;;value pair exists.
     *
     * @return a delimited string of one or more delimited name/value pairs
     */
    public String getParamString(Map<String, String> params) {
        return getParamString(new StringBuilder(), params);
    }

    /**
     * Get signed audit parameters as a string.
     *
     * This method is called to convert parameters into a
     * string of name;;value pairs separated by a '+'
     * if more than one name;;value pair exists.
     *
     * @return a delimited string of one or more delimited name/value pairs
     */
    public String getParamString(StringBuilder parameters, Map<String, String> params) {

        if (params == null)
            return parameters.toString();

        SignedAuditEvent.encodeMap(parameters, params);

        return parameters.toString();
    }

    public LogEvent create(int level, String msg, Object[] params, boolean multiline) {
        return signedAuditLogger.create(level, msg, params, multiline);
    }

    public void log(String message) {
        signedAuditLogger.log(message);
    }

    public void log(LogEvent event) {
        signedAuditLogger.log(event);
    }
}
