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
package com.netscape.cms.evaluators;

import java.util.Arrays;

import org.dogtagpki.server.authentication.AuthToken;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.evaluators.AccessEvaluator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;

/**
 * A class represents a group acls evaluator.
 */
public class GroupAccessEvaluator extends AccessEvaluator {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GroupAccessEvaluator.class);

    /**
     * Class constructor.
     */
    public GroupAccessEvaluator() {
        this.type = "group";
        this.description = "group membership evaluator";
    }

    @Override
    public void init() {
        logger.debug("GroupAccessEvaluator: init");
    }

    @Override
    public String[] getSupportedOperators() {
        String[] s = new String[2];

        s[0] = "=";
        s[1] = "!=";
        return s;
    }

    /**
     * evaluates uid in AuthToken to see if it has membership in
     * group value
     *
     * @param authToken authentication token
     * @param type must be "at_group"
     * @param op must be "="
     * @param value the group name
     * @return true if AuthToken uid belongs to the group value,
     *         false otherwise
     */
    @Override
    public boolean evaluate(AuthToken authToken, String type, String op, String value) {

        UGSubsystem ug = engine.getUGSubsystem();

        if (type.equals(this.type)) {
            // should define "uid" at a common place
            String uid = null;

            uid = authToken.getInString(AuthToken.USER_ID);
            if (uid == null) {
                uid = authToken.getInString(AuthToken.UID);
                if (uid == null) {
                    logger.warn("GroupAccessEvaluator: " + CMS.getLogMessage("EVALUTOR_UID_NULL"));
                    return false;
                }
            }
            logger.debug("GroupAccessEvaluator: evaluate: uid=" + uid + " value=" + value);

            String[] groups = authToken.getInStringArray(AuthToken.GROUPS);
            if (groups != null) {
                boolean matched = Arrays.asList(groups).contains(Utils.stripQuotes(value));
                if (op.equals("="))
                    return matched;
                else if (op.equals("!="))
                    return !matched;
            } else {
                logger.debug("GroupAccessEvaluator: evaluate: no groups in authToken");
                User id = null;
                try {
                    id = ug.getUser(uid);
                } catch (EBaseException e) {
                    logger.warn("GroupAccessEvaluator: " + e.getMessage(), e);
                    return false;
                }

                if (op.equals("=")) {
                    return ug.isMemberOf(id, Utils.stripQuotes(value));
                } else if (op.equals("!=")) {
                    return !(ug.isMemberOf(id, Utils.stripQuotes(value)));
                }
            }
        }

        return false;
    }

    /**
     * evaluates uid in SessionContext to see if it has membership in
     * group value
     *
     * @param type must be "group"
     * @param op must be "="
     * @param value the group name
     * @return true if SessionContext uid belongs to the group value,
     *         false otherwise
     */
    @Override
    public boolean evaluate(String type, String op, String value) {

        UGSubsystem ug = engine.getUGSubsystem();
        SessionContext mSC = SessionContext.getContext();

        if (type.equals(this.type)) {
            User id = (User) mSC.get(SessionContext.USER);

            if (id == null) {
                logger.warn("GroupAccessEvaluator: " + CMS.getLogMessage("EVALUTOR_UID_NULL"));
                return false;
            }
            boolean isMemberOfGroup = ug.isMemberOf(id, Utils.stripQuotes(value));
            return op.equals("=") ? isMemberOfGroup : !isMemberOfGroup;
        }

        return false;
    }
}
