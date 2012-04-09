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
package com.netscape.cms.authorization;

// cert server imports.
import com.netscape.certsrv.acls.EACLsException;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzInternalError;
import com.netscape.certsrv.authorization.IAuthzManager;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.logging.ILogger;

/**
 * A class for basic acls authorization manager
 *
 * @version $Revision$, $Date$
 */
public class BasicAclAuthz extends AAclAuthz
        implements IAuthzManager, IExtendedPluginInfo {

    // members

    /* name of this authorization manager instance */
    private String mName = null;

    /* name of the authorization manager plugin */
    private String mImplName = null;

    /* configuration store */
    @SuppressWarnings("unused")
    private IConfigStore mConfig;

    /* the system logger */
    private ILogger mLogger = null;

    protected static final String PROP_BASEDN = "basedn";

    static {
        mExtendedPluginInfo.add("nothing for now");
    }

    /**
     * Default constructor
     */
    public BasicAclAuthz() {

        /* Holds configuration parameters accepted by this implementation.
         * This list is passed to the configuration console so configuration
         * for instances of this implementation can be configured through the
         * console.
         */
        mConfigParams =
                new String[] {
                    "dummy"
                };
    }

    /**
     *
     */
    public void init(String name, String implName, IConfigStore config)
            throws EBaseException {
        mName = name;
        mImplName = implName;
        mConfig = config;
        mLogger = CMS.getLogger();

        super.init(config);

        log(ILogger.LL_INFO, "initialization done");
    }

    /**
     * gets the name of this authorization manager instance
     */
    public String getName() {
        return mName;
    }

    /**
     * gets the plugin name of this authorization manager.
     */
    public String getImplName() {
        return mImplName;
    }

    /**
     * check the authorization permission for the user associated with
     * authToken on operation
     * <p>
     * Example:
     * <p>
     * For example, if UsrGrpAdminServlet needs to authorize the caller it would do be done in the following fashion:
     *
     * <PRE>
     * try {
     *     authzTok = mAuthz.authorize(&quot;DirACLBasedAuthz&quot;, authToken, RES_GROUP, &quot;read&quot;);
     * } catch (EBaseException e) {
     *     log(ILogger.LL_FAILURE, &quot;authorize call: &quot; + e.toString());
     * }
     * </PRE>
     *
     * @param authToken the authToken associated with a user
     * @param resource - the protected resource name
     * @param operation - the protected resource operation name
     * @exception EAuthzInternalError if an internal error occurred.
     * @exception EAuthzAccessDenied if access denied
     * @return authzToken if success
     */
    public AuthzToken authorize(IAuthToken authToken, String resource, String operation)
            throws EAuthzInternalError, EAuthzAccessDenied {
        AuthzToken authzToken = new AuthzToken(this);

        try {
            checkPermission(authToken, resource, operation);

            CMS.debug("BasicAclAuthz: authorization passed");

            // compose AuthzToken
            authzToken.set(AuthzToken.TOKEN_AUTHZ_RESOURCE, resource);
            authzToken.set(AuthzToken.TOKEN_AUTHZ_OPERATION, operation);
            authzToken.set(AuthzToken.TOKEN_AUTHZ_STATUS,
                    AuthzToken.AUTHZ_STATUS_SUCCESS);
        } catch (EACLsException e) {
            // audit here later
            log(ILogger.LL_FAILURE, CMS.getLogMessage("AUTHZ_EVALUATOR_AUTHORIZATION_FAILED"));
            String params[] = { resource, operation };

            throw new EAuthzAccessDenied(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZ_ACCESS_DENIED", params));
        }

        return authzToken;
    }

    public AuthzToken authorize(IAuthToken authToken, String expression)
            throws EAuthzAccessDenied {
        if (evaluateACLs(authToken, expression)) {
            return (new AuthzToken(this));
        } else {
            String params[] = { expression };
            throw new EAuthzAccessDenied(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZ_ACCESS_DENIED", params));
        }
    }

    /**
     * This currently does not flush to permanent storage
     *
     * @param id is the resource id
     * @param strACLs
     */
    public void updateACLs(String id, String rights, String strACLs,
            String desc) throws EACLsException {
        try {
            super.updateACLs(id, rights, strACLs, desc);
            //            flushResourceACLs();
        } catch (EACLsException ex) {

            log(ILogger.LL_FAILURE, CMS.getLogMessage("AUTHZ_EVALUATOR_FLUSH_RESOURCES", ex.toString()));

            throw new EACLsException(CMS.getUserMessage("CMS_ACL_UPDATE_FAIL"));
        }
    }

    /**
     * updates resourceACLs to permanent storage.
     * currently not implemented for this authzMgr
     */
    protected void flushResourceACLs() throws EACLsException {
        log(ILogger.LL_FAILURE, "flushResourceACL() is not implemented");
        throw new EACLsException(CMS.getUserMessage("CMS_ACL_METHOD_NOT_IMPLEMENTED"));
    }

    /**
     * graceful shutdown
     */
    public void shutdown() {
        log(ILogger.LL_INFO, "shutting down");
    }

    /**
     * Logs a message for this class in the system log file.
     *
     * @param level The log level.
     * @param msg The message to log.
     * @see com.netscape.certsrv.logging.ILogger
     */
    protected void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_AUTHORIZATION,
                level, msg);
    }
}
