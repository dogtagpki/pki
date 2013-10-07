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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.evaluators.IAccessEvaluator;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cmsutil.util.Utils;

/**
 * A class represents a user acls evaluator.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class UserAccessEvaluator implements IAccessEvaluator {
    private String mType = "user";
    private String mDescription = "user equivalence evaluator";
    private ILogger mLogger = CMS.getLogger();

    private final static String ANYBODY = "anybody";
    private final static String EVERYBODY = "everybody";

    /**
     * Class constructor.
     */
    public UserAccessEvaluator() {
    }

    /**
     * initialization. nothing for now.
     */
    public void init() {
        CMS.debug("UserAccessEvaluator: init");
    }

    /**
     * gets the type name for this acl evaluator
     *
     * @return type for this acl evaluator: "user" or "at_user"
     */
    public String getType() {
        return mType;
    }

    /**
     * gets the description for this acl evaluator
     *
     * @return description for this acl evaluator
     */
    public String getDescription() {
        return mDescription;
    }

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
    public boolean evaluate(IAuthToken authToken, String type, String op, String value) {

        if (type.equals(mType)) {
            String s = Utils.stripQuotes(value);

            if ((s.equals(ANYBODY) || s.equals(EVERYBODY)) && op.equals("="))
                return true;

            // should define "uid" at a common place
            String uid = null;

            uid = authToken.getInString("uid");

            if (uid == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("EVALUTOR_UID_IS_NULL"));
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
    public boolean evaluate(String type, String op, String value) {

        SessionContext mSC = SessionContext.getContext();

        if (type.equals(mType)) {
            String s = Utils.stripQuotes(value);

            if (s.equals(ANYBODY) && op.equals("="))
                return true;

            IUser id = (IUser) mSC.get(SessionContext.USER);

            if (op.equals("="))
                return s.equalsIgnoreCase(id.getName());
            else if (op.equals("!="))
                return !(s.equalsIgnoreCase(id.getName()));
        }

        return false;
    }

    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_ACLS,
                level, "UserAccessEvaluator: " + msg);
    }

}
