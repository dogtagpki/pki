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
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.evaluators.IAccessEvaluator;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cmsutil.util.Utils;

/**
 * A class represents a group acls evaluator.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class GroupAccessEvaluator implements IAccessEvaluator {
    private String mType = "group";
    private IUGSubsystem mUG = null;
    private String mDescription = "group membership evaluator";
    private ILogger mLogger = CMS.getLogger();

    /**
     * Class constructor.
     */
    public GroupAccessEvaluator() {

        mUG = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);

        if (mUG == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("EVALUTOR_UG_NULL"));
        }
    }

    /**
     * initialization. nothing for now.
     */
    public void init() {
        CMS.debug("GroupAccessEvaluator: init");
    }

    /**
     * gets the type name for this acl evaluator
     *
     * @return type for this acl evaluator: "group" or "at_group"
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
    public boolean evaluate(IAuthToken authToken, String type, String op, String value) {

        if (type.equals(mType)) {
            // should define "uid" at a common place
            String uid = null;

            uid = authToken.getInString("userid");
            if (uid == null) {
                uid = authToken.getInString("uid");
                if (uid == null) {
                    CMS.debug("GroupAccessEvaluator: evaluate: uid null");
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("EVALUTOR_UID_NULL"));
                    return false;
                }
            }
            CMS.debug("GroupAccessEvaluator: evaluate: uid=" + uid + " value=" + value);

            String groupname = authToken.getInString("gid");

            if (groupname != null) {
                CMS.debug("GroupAccessEvaluator: evaluate: authToken gid=" + groupname);
                if (op.equals("=")) {
                    return groupname.equals(Utils.stripQuotes(value));
                } else if (op.equals("!=")) {
                    return !groupname.equals(Utils.stripQuotes(value));
                }
            } else {
                CMS.debug("GroupAccessEvaluator: evaluate: no gid in authToken");
                IUser id = null;
                try {
                    id = mUG.getUser(uid);
                } catch (EBaseException e) {
                    CMS.debug("GroupAccessEvaluator: " + e.toString());
                    return false;
                }

                if (op.equals("=")) {
                    return mUG.isMemberOf(id, Utils.stripQuotes(value));
                } else if (op.equals("!=")) {
                    return !(mUG.isMemberOf(id, Utils.stripQuotes(value)));
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
    public boolean evaluate(String type, String op, String value) {

        SessionContext mSC = SessionContext.getContext();

        if (type.equals(mType)) {
            IUser id = (IUser) mSC.get(SessionContext.USER);

            if (id == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("EVALUTOR_UID_NULL"));
                return false;
            }
            if (op.equals("="))
                return mUG.isMemberOf(id, Utils.stripQuotes(value));
            else
                return !(mUG.isMemberOf(id, Utils.stripQuotes(value)));

        }

        return false;
    }

    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_ACLS,
                level, "GroupAccessEvaluator: " + msg);
    }

}
