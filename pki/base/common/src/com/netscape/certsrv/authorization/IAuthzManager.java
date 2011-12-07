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
package com.netscape.certsrv.authorization;

import java.util.Enumeration;
import java.util.Hashtable;

import com.netscape.certsrv.acls.EACLsException;
import com.netscape.certsrv.acls.IACL;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.evaluators.IAccessEvaluator;

/**
 * Authorization Manager interface needs to be implemented by all authorization
 * managers.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface IAuthzManager {

    /**
     * Get the name of this authorization manager instance.
     * <p>
     * 
     * @return String the name of this authorization manager.
     */
    public String getName();

    /**
     * Get implementation name of authorization manager plugin.
     * <p>
     * An example of an implementation name will be:
     * 
     * <PRE>
     * com.netscape.cms.BasicAclAuthz
     * </PRE>
     * <p>
     * 
     * @return The name of the authorization manager plugin.
     */
    public String getImplName();

    /**
     * <code>accessInit</code> is for servlets who want to initialize their own
     * authorization information before full operation. It is supposed to be
     * called from the authzMgrAccessInit() method of the AuthzSubsystem.
     * <p>
     * The accessInfo format is determined by each individual authzmgr. For
     * example, for BasicAclAuthz, The accessInfo is the resACLs, whose format
     * should conform to the following:
     * 
     * <pre>
     *    <resource ID>:right-1[,right-n]:[allow,deny](right(s))<evaluatorType>=<value>:<comment for this resource acl
     * </pre>
     * <P>
     * Example: resTurnKnob:left,right:allow(left) group="lefties":door knobs
     * for lefties
     * 
     * @param accessInfo the access info string in the format specified in the
     *            authorization manager
     * @exception EBaseException error parsing the accessInfo
     */
    public void accessInit(String accessInfo) throws EBaseException;

    /**
     * Check if the user is authorized to perform the given operation on the
     * given resource.
     * 
     * @param authToken the authToken associated with a user.
     * @param resource - the protected resource name
     * @param operation - the protected resource operation name
     * @return authzToken if the user is authorized
     * @exception EAuthzInternalError if an internal error occurred.
     * @exception EAuthzAccessDenied if access denied
     */
    public AuthzToken authorize(IAuthToken authToken, String resource,
            String operation) throws EAuthzInternalError, EAuthzAccessDenied;

    public AuthzToken authorize(IAuthToken authToken, String expression)
            throws EAuthzInternalError, EAuthzAccessDenied;

    /**
     * Initialize this authorization manager.
     * 
     * @param name The name of this authorization manager instance.
     * @param implName The name of the authorization manager plugin.
     * @param config The configuration store for this authorization manager.
     * @exception EBaseException If an initialization error occurred.
     */
    public void init(String name, String implName, IConfigStore config)
            throws EBaseException;

    /**
     * Prepare this authorization manager for a graceful shutdown. Called when
     * the server is exiting for any cleanup needed.
     */
    public void shutdown();

    /**
     * Get configuration parameters for this implementation. The configuration
     * parameters returned is passed to the console so configuration for
     * instances of this implementation can be made through the console.
     * 
     * @return a list of names for configuration parameters.
     * @exception EBaseException If an internal error occurred
     */
    public String[] getConfigParams() throws EBaseException;

    /**
     * Get the configuration store for this authorization manager.
     * 
     * @return The configuration store of this authorization manager.
     */
    public IConfigStore getConfigStore();

    /**
     * Get ACL entries
     * 
     * @return enumeration of ACL entries.
     */
    public Enumeration getACLs();

    /**
     * Get individual ACL entry for the given name of entry.
     * 
     * @param target The name of the ACL entry
     * @return The ACL entry.
     */
    public IACL getACL(String target);

    /**
     * Update ACLs in the database
     * 
     * @param id The name of the ACL entry (ie, resource id)
     * @param rights The allowable rights for this resource
     * @param strACLs The value of the ACL entry
     * @param desc The description for this resource
     * @exception EACLsException when update fails.
     */
    public void updateACLs(String id, String rights, String strACLs, String desc)
            throws EACLsException;

    /**
     * Get all registered evaluators.
     * 
     * @return All registered evaluators.
     */
    public Enumeration aclEvaluatorElements();

    /**
     * Register new evaluator
     * 
     * @param type Type of evaluator
     * @param evaluator Value of evaluator
     */
    public void registerEvaluator(String type, IAccessEvaluator evaluator);

    /**
     * Return a table of evaluators
     * 
     * @return A table of evaluators
     */
    public Hashtable getAccessEvaluators();
}
