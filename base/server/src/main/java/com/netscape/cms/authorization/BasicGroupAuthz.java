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
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.authorization;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzManager;
import org.dogtagpki.server.authorization.AuthzManagerConfig;
import org.dogtagpki.server.authorization.AuthzToken;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.acls.EACLsException;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzInternalError;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.evaluators.IAccessEvaluator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;

public class BasicGroupAuthz extends AuthzManager implements IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(BasicGroupAuthz.class);

    private static final String GROUP = "group";

    /* group that is allowed to access resources */
    private String groupName;

    /* Vector of extendedPluginInfo strings */
    protected static Vector<String> extendedPluginInfo;

    protected static String[] configParams;

    static {
        extendedPluginInfo = new Vector<>();
        extendedPluginInfo.add("group;string,required;" +
                "Group to permit access");
    }

    public BasicGroupAuthz() {
        configParams = new String[] {"group"};
    }

    @Override
    public String[] getExtendedPluginInfo() {
        return Utils.getStringArrayFromVector(extendedPluginInfo);
    }

    @Override
    public void accessInit(String accessInfo) throws EBaseException {
        // TODO Auto-generated method stub

    }

    @Override
    public AuthzToken authorize(AuthToken authToken, String resource, String operation)
            throws EAuthzInternalError, EAuthzAccessDenied {
        String user = authToken.getInString(AuthToken.USER_ID);
        if (user == null) {
            throw new EAuthzAccessDenied("No userid provided");
        }

        CMSEngine engine = CMS.getCMSEngine();
        UGSubsystem ug = engine.getUGSubsystem();
        Group group = ug.getGroupFromName(groupName);
        if (!group.isMember(user)) {
            logger.error("BasicGroupAuthz: access denied. User: " + user + " is not a member of group: " + groupName);
            throw new EAuthzAccessDenied("Access denied");
        }

        logger.debug("BasicGroupAuthz: authorization passed");

        // compose AuthzToken
        AuthzToken authzToken = new AuthzToken(this);
        authzToken.set(AuthzToken.TOKEN_AUTHZ_RESOURCE, resource);
        authzToken.set(AuthzToken.TOKEN_AUTHZ_OPERATION, operation);
        authzToken.set(AuthzToken.TOKEN_AUTHZ_STATUS, AuthzToken.AUTHZ_STATUS_SUCCESS);

        return authzToken;
    }

    @Override
    public AuthzToken authorize(AuthToken authToken, String expression)
            throws EAuthzInternalError, EAuthzAccessDenied {
        return authorize(authToken, null, null);
    }

    @Override
    public void init(String name, String implName, AuthzManagerConfig config) throws EBaseException {
        this.name = name;
        this.implName = implName;
        this.config = config;

        groupName = config.getString(GROUP);
    }

    @Override
    public void shutdown() {
        // TODO Auto-generated method stub
    }

    @Override
    public String[] getConfigParams() throws EBaseException {
        return configParams;
    }

    @Override
    public Enumeration<ACL> getACLs() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public ACL getACL(String target) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void updateACLs(String id, String rights, String strACLs, String desc) throws EACLsException {
        // TODO Auto-generated method stub

    }

    @Override
    public Enumeration<IAccessEvaluator> aclEvaluatorElements() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void registerEvaluator(String type, IAccessEvaluator evaluator) {
        // TODO Auto-generated method stub

    }

    @Override
    public Hashtable<String, IAccessEvaluator> getAccessEvaluators() {
        // TODO Auto-generated method stub
        return null;
    }

}
