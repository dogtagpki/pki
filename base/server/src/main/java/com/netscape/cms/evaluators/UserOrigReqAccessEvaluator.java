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
// (C) 2008 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.evaluators;

import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.evaluators.IAccessEvaluator;
import com.netscape.cmscore.usrgrp.User;

/**
 * A class represents a user-origreq user mapping acls evaluator.
 * This is primarily used for renewal. During renewal, the orig_req
 * uid is placed in the SessionContext of the renewal session context
 * to be evaluated by this evaluator
 * <P>
 *
 * @author Christina Fu
 * @version $Revision$, $Date$
 */
public class UserOrigReqAccessEvaluator implements IAccessEvaluator {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserOrigReqAccessEvaluator.class);

    private String mType = "user_origreq";
    private String mDescription = "user origreq matching evaluator";

    private final static String ANYBODY = "anybody";
    private final static String EVERYBODY = "everybody";

    /**
     * Class constructor.
     */
    public UserOrigReqAccessEvaluator() {
    }

    /**
     * initialization. nothing for now.
     */
    @Override
    public void init() {
        logger.debug("UserOrigReqAccessEvaluator: init");
    }

    /**
     * gets the type name for this acl evaluator
     *
     * @return type for this acl evaluator: "user_origreq" or "at_user_origreq"
     */
    @Override
    public String getType() {
        return mType;
    }

    /**
     * gets the description for this acl evaluator
     *
     * @return description for this acl evaluator
     */
    @Override
    public String getDescription() {
        return mDescription;
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
     * @param type must be "at_userreq"
     * @param op must be "="
     * @param value the request param name
     * @return true if AuthToken userid is same as value, false otherwise
     */
    @Override
    public boolean evaluate(IAuthToken authToken, String type, String op, String value) {
        logger.debug("UserOrigReqAccessEvaluator: evaluate() begins");
        if (type.equals(mType)) {
            String s = Utils.stripQuotes(value);

            if ((s.equals(ANYBODY) || s.equals(EVERYBODY)) && op.equals("="))
                return true;

            // should define "userid" at a common place
            String userid = null;

            userid = authToken.getInString("userid");

            if (userid == null) {
                logger.warn("UserOrigReqAccessEvaluator: evaluate() userid in authtoken null");
                return false;
            } else
                logger.debug("UserOrigReqAccessEvaluator: evaluate() userid in authtoken =" + userid);

            // find value of param in request
            SessionContext mSC = SessionContext.getContext();
            logger.debug("UserOrigReqAccessEvaluator: evaluate() getting " + "orig_req." + s + " in SessionContext");
            // "orig_req.auth_token.uid"
            String orig_id = (String) mSC.get("orig_req." + s);

            if (orig_id == null) {
                logger.warn("UserOrigReqAccessEvaluator: evaluate() orig_id null");
                return false;
            }
            logger.debug("UserOrigReqAccessEvaluator: evaluate() orig_id =" + orig_id);
            if (op.equals("="))
                return userid.equalsIgnoreCase(orig_id);
            else if (op.equals("!="))
                return !(userid.equalsIgnoreCase(orig_id));
        }

        return false;
    }

    /**
     * Evaluates the user in session context to see if it's equal to value
     *
     * @param type must be "user_origreq"
     * @param op must be "="
     * @param value the user id
     * @return true if SessionContext uid is same as value, false otherwise
     */
    @Override
    public boolean evaluate(String type, String op, String value) {

        SessionContext mSC = SessionContext.getContext();

        if (type.equals(mType)) {
            // what do I do with s here?
            String s = Utils.stripQuotes(value);

            if (s.equals(ANYBODY) && op.equals("="))
                return true;

            User id = (User) mSC.get(SessionContext.USER);
            // "orig_req.auth_token.uid"
            String orig_id = (String) mSC.get("orig_req" + s);

            if (op.equals("="))
                return id.getUserID().equalsIgnoreCase(orig_id);
            else if (op.equals("!="))
                return !(id.getUserID().equalsIgnoreCase(orig_id));
        }

        return false;
    }

}
