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
import java.util.Locale;
import java.util.Vector;

import com.netscape.certsrv.acls.ACL;
import com.netscape.certsrv.acls.EACLsException;
import com.netscape.certsrv.acls.IACL;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzInternalError;
import com.netscape.certsrv.authorization.IAuthzManager;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.evaluators.IAccessEvaluator;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.cmsutil.util.Utils;

public class BasicGroupAuthz implements IAuthzManager, IExtendedPluginInfo {

    private static final String GROUP = "group";

    /* name of this authorization manager instance */
    private String name = null;

    /* name of the authorization manager plugin */
    private String implName = null;

    /* configuration store */
    private IConfigStore config;

    /* group that is allowed to access resources */
    private String groupName = null;

    /* Vector of extendedPluginInfo strings */
    protected static Vector<String> mExtendedPluginInfo = null;

    protected static String[] mConfigParams = null;

    static {
        mExtendedPluginInfo = new Vector<String>();
        mExtendedPluginInfo.add("group;string,required;" +
                "Group to permit access");
    }

    public BasicGroupAuthz() {
        mConfigParams = new String[] {"group"};
    }

    @Override
    public String[] getExtendedPluginInfo(Locale locale) {
        String[] s = Utils.getStringArrayFromVector(mExtendedPluginInfo);
        return s;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getImplName() {
        return implName;
    }

    @Override
    public void accessInit(String accessInfo) throws EBaseException {
        // TODO Auto-generated method stub

    }

    @Override
    public AuthzToken authorize(IAuthToken authToken, String resource, String operation)
            throws EAuthzInternalError, EAuthzAccessDenied {
        String user = authToken.getInString(IAuthToken.USER_ID);
        if (user == null) {
            throw new EAuthzAccessDenied("No userid provided");
        }

        IUGSubsystem ug = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);
        IGroup group = ug.getGroupFromName(groupName);
        if (!group.isMember(user)) {
            throw new EAuthzAccessDenied("Access denied");
        }

        CMS.debug("BasicGroupAuthz: authorization passed");

        // compose AuthzToken
        AuthzToken authzToken = new AuthzToken(this);
        authzToken.set(AuthzToken.TOKEN_AUTHZ_RESOURCE, resource);
        authzToken.set(AuthzToken.TOKEN_AUTHZ_OPERATION, operation);
        authzToken.set(AuthzToken.TOKEN_AUTHZ_STATUS, AuthzToken.AUTHZ_STATUS_SUCCESS);

        return authzToken;
    }

    @Override
    public AuthzToken authorize(IAuthToken authToken, String expression)
            throws EAuthzInternalError, EAuthzAccessDenied {
        return authorize(authToken, null, null);
    }

    @Override
    public void init(String name, String implName, IConfigStore config) throws EBaseException {
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
        return mConfigParams;
    }

    @Override
    public IConfigStore getConfigStore() {
        return config;
    }

    @Override
    public Enumeration<ACL> getACLs() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public IACL getACL(String target) {
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
