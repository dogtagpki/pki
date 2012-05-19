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

package com.netscape.certsrv.logging;

import java.util.Map;

/**
 * @author Endi S. Dewata
 */
public interface IAuditor {

    public final static String LOGGING_SIGNED_AUDIT_CONFIG_ROLE =
            "LOGGING_SIGNED_AUDIT_CONFIG_ROLE_3";

    public final static String SIGNED_AUDIT_SCOPE = "Scope";
    public final static String SIGNED_AUDIT_OPERATION = "Operation";
    public final static String SIGNED_AUDIT_RESOURCE = "Resource";
    public final static String SIGNED_AUDIT_RULENAME = "RULENAME";
    public final static String SIGNED_AUDIT_PASSWORD_VALUE = "********";
    public final static String SIGNED_AUDIT_EMPTY_NAME_VALUE_PAIR = "Unknown";
    public final static String SIGNED_AUDIT_NAME_VALUE_DELIMITER = ";;";
    public final static String SIGNED_AUDIT_NAME_VALUE_PAIRS_DELIMITER = "+";

    /**
     * Get signed audit log subject ID
     *
     * This method is called to obtain the "SubjectID" for
     * a signed audit log message.
     *
     * @return id string containing the signed audit log message SubjectID
     */
    public String getSubjectID();

    /**
     * Get signed audit groups
     *
     * This method is called to extract all "groups" associated
     * with the "auditSubjectID()".
     * <P>
     *
     * @param subjectID string containing the signed audit log message SubjectID
     * @return a delimited string of groups associated
     *         with the "auditSubjectID()"
     */
    public String getGroups(String subjectID);

        /**
     * Get signed audit parameters as a string.
     *
     * This method is called to convert parameters into a
     * string of name;;value pairs separated by a '+'
     * if more than one name;;value pair exists.
     *
     * @return a delimited string of one or more delimited name/value pairs
     */
    public String getParamString(String scope, String type, String id, Map<String, String> params);

    /**
     * Log audit message.
     */
    public void log(String message);
}