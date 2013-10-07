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

import java.util.Enumeration;
import java.util.Map;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.logging.IAuditor;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;

/**
 * @author Endi S. Dewata
 */
public class Auditor implements IAuditor {

    public final static Auditor auditor = new Auditor();

    public ILogger signedAuditLogger = CMS.getSignedAuditLogger();

    public static IAuditor getAuditor() {
        return auditor;
    }

    @Override
    public String getSubjectID() {
        // if no signed audit object exists, bail
        if (signedAuditLogger == null) return null;

        SessionContext context = SessionContext.getExistingContext();
        if (context == null) return ILogger.UNIDENTIFIED;

        // Initialize subject ID
        String subjectID = (String)context.get(SessionContext.USER_ID);
        if (subjectID == null) return ILogger.NONROLEUSER;

        return subjectID.trim();
    }

    @Override
    public String getGroups(String subjectID) {
        // if no signed audit object exists, bail
        if (signedAuditLogger == null) return null;

        if (subjectID == null || subjectID.equals(ILogger.UNIDENTIFIED))
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        Enumeration<IGroup> groups;

        try {
            IUGSubsystem userGroupSubsystem = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);
            groups = userGroupSubsystem.findGroups("*");

        } catch (Exception e) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        StringBuilder sb = new StringBuilder();

        while (groups.hasMoreElements()) {
            IGroup group = groups.nextElement();

            if (group.isMember(subjectID) == true) {
                if (sb.length() != 0) sb.append(", ");
                sb.append(group.getGroupID());
            }
        }

        if (sb.length() == 0) return ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        return sb.toString();
    }

    @Override
    public String getParamString(String scope, String type, String id, Map<String, String> params) {

        // if no signed audit object exists, bail
        if (signedAuditLogger == null) return null;
        StringBuilder parameters = new StringBuilder();

        // always identify the scope of the request
        if (scope != null) {
            parameters.append(SIGNED_AUDIT_SCOPE
                    + SIGNED_AUDIT_NAME_VALUE_DELIMITER
                    + scope);
        } else {
            parameters.append(SIGNED_AUDIT_EMPTY_NAME_VALUE_PAIR);
        }

        // identify the operation type of the request
        if (type != null) {
            parameters.append(SIGNED_AUDIT_NAME_VALUE_PAIRS_DELIMITER);

            parameters.append(SIGNED_AUDIT_OPERATION
                    + SIGNED_AUDIT_NAME_VALUE_DELIMITER
                    + type);
        }

        // identify the resource type of the request
        if (id != null) {
            parameters.append(SIGNED_AUDIT_NAME_VALUE_PAIRS_DELIMITER);

            parameters.append(SIGNED_AUDIT_RESOURCE
                    + SIGNED_AUDIT_NAME_VALUE_DELIMITER
                    + id);
        }

        if (params == null) return parameters.toString();

        // identify any remaining request parameters

        for (Map.Entry<String,String> entry : params.entrySet() ) {
            String name = entry.getKey();

            // skip "RULENAME" parameter
            if (name.equals(SIGNED_AUDIT_RULENAME)) continue;

            parameters.append(SIGNED_AUDIT_NAME_VALUE_PAIRS_DELIMITER);

            String value = entry.getValue();

            if (value == null) {
                parameters.append(name
                        + SIGNED_AUDIT_NAME_VALUE_DELIMITER
                        + ILogger.SIGNED_AUDIT_EMPTY_VALUE);
                continue;
            }

            value = value.trim();

            if (value.equals("")) {
                parameters.append(name
                        + SIGNED_AUDIT_NAME_VALUE_DELIMITER
                        + ILogger.SIGNED_AUDIT_EMPTY_VALUE);
                continue;
            }

            //
            // To fix Blackflag Bug # 613800:
            //
            //     Check "com.netscape.certsrv.common.Constants" for
            //     case-insensitive "password", "pwd", and "passwd"
            //     name fields, and hide any password values:
            //
            if (name.equals(Constants.PASSWORDTYPE) || /* "password" */
                    name.equals(Constants.TYPE_PASSWORD) ||
                    name.equals(Constants.PR_USER_PASSWORD) ||
                    name.equals(Constants.PT_OLD_PASSWORD) ||
                    name.equals(Constants.PT_NEW_PASSWORD) ||
                    name.equals(Constants.PT_DIST_STORE) ||
                    name.equals(Constants.PT_DIST_EMAIL) ||
                    /* "pwd" */name.equals(Constants.PR_AUTH_ADMIN_PWD) ||
                    // ignore this one  name.equals( Constants.PR_BINDPWD_PROMPT )        ||
                    name.equals(Constants.PR_DIRECTORY_MANAGER_PWD) ||
                    name.equals(Constants.PR_OLD_AGENT_PWD) ||
                    name.equals(Constants.PR_AGENT_PWD) ||
                    name.equals(Constants.PT_PUBLISH_PWD) ||
                    /* "passwd" */name.equals(Constants.PR_BIND_PASSWD) ||
                    name.equals(Constants.PR_BIND_PASSWD_AGAIN) ||
                    name.equals(Constants.PR_TOKEN_PASSWD)) {

                // hide password value
                parameters.append(name
                        + SIGNED_AUDIT_NAME_VALUE_DELIMITER
                        + SIGNED_AUDIT_PASSWORD_VALUE);

            } else {
                // process normally
                parameters.append(name
                        + SIGNED_AUDIT_NAME_VALUE_DELIMITER
                        + value);
            }
        }

        return parameters.toString();
    }

    @Override
    public void log(String message) {

        if (signedAuditLogger == null) return;

        signedAuditLogger.log(
                ILogger.EV_SIGNED_AUDIT,
                null,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY,
                message);
    }
}
