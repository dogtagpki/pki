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

import org.dogtagpki.server.authentication.AuthToken;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.evaluators.AccessEvaluator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.usrgrp.User;

/**
 * A class represents a user acls evaluator.
 */
public class UserAccessEvaluator extends AccessEvaluator {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserAccessEvaluator.class);

    private final static String ANYBODY = "anybody";
    private final static String EVERYBODY = "everybody";

    /**
     * Class constructor.
     */
    public UserAccessEvaluator() {
        this.type = "user";
        this.description = "user equivalence evaluator";
    }

    /**
     * initialization. nothing for now.
     */
    @Override
    public void init() {
        logger.debug("UserAccessEvaluator: init");
    }

    @Override
    public String[] getSupportedOperators() {
        String[] s = new String[2];

        s[0] = "=";
        s[1] = "!=";
        return s;
    }

    /**
     * Evaluates the user in AuthToken to see if it's equal to value
     *
     * @param authToken AuthToken from authentication
     * @param type must be "at_user"
     * @param op must be "="
     * @param value the user id
     * @return true if AuthToken uid is same as value, false otherwise
     */
    @Override
    public boolean evaluate(AuthToken authToken, String type, String op, String value) {

        if (type.equals(this.type)) {
            String s = Utils.stripQuotes(value);

            if ((s.equals(ANYBODY) || s.equals(EVERYBODY)) && op.equals("="))
                return true;

            // user should be authenticated at this point.
            if (authToken == null) return false;

            // should define "uid" at a common place
            String uid = null;

            uid = authToken.getInString("uid");

            if (uid == null) {
                logger.warn("UserAccessEvaluator: " + CMS.getLogMessage("EVALUTOR_UID_IS_NULL"));
                return false;
            }

            if (op.equals("="))
                return s.equalsIgnoreCase(uid);
            else if (op.equals("!="))
                return !(s.equalsIgnoreCase(uid));
        }

        return false;
    }

    /**
     * Evaluates the user in session context to see if it's equal to value
     *
     * @param type must be "user"
     * @param op must be "="
     * @param value the user id
     * @return true if SessionContext uid is same as value, false otherwise
     */
    @Override
    public boolean evaluate(String type, String op, String value) {

        SessionContext mSC = SessionContext.getContext();

        if (type.equals(this.type)) {
            String s = Utils.stripQuotes(value);

            if (s.equals(ANYBODY) && op.equals("="))
                return true;

            User id = (User) mSC.get(SessionContext.USER);

            if (op.equals("="))
                return s.equalsIgnoreCase(id.getUserID());
            else if (op.equals("!="))
                return !(s.equalsIgnoreCase(id.getUserID()));
        }

        return false;
    }
}
