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

import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;

import com.netscape.certsrv.base.IAttrSet;

/**
 * Authorization token returned by Authorization Managers.
 * Upon return, it contains the name of the authorization manager that create
 * the AuthzToken, the plugin name of the authorization manager, time of
 * authorization happened, name of the resource, type of operation performed
 * on the resource.
 * <p>
 * 
 * @version $Revision$, $Date$
 */
public class AuthzToken implements IAttrSet {
    private static final long serialVersionUID = 4716145610877112054L;
    private Hashtable<String, Object> mAttrs = null;

    /**
     * Plugin name of the authorization manager that created the
     * AuthzToken as a string.
     */
    public static final String TOKEN_AUTHZMGR_IMPL_NAME = "authzMgrImplName";

    /**
     * Name of the authorization manager that created the AuthzToken
     * as a string.
     */
    public static final String TOKEN_AUTHZMGR_INST_NAME = "authzMgrInstName";

    /**
     * Time of authorization as a java.util.Date
     */
    public static final String TOKEN_AUTHZTIME = "authzTime";

    /**
     * name of the resource
     */
    public static final String TOKEN_AUTHZ_RESOURCE = "authzRes";

    /**
     * name of the operation
     */
    public static final String TOKEN_AUTHZ_OPERATION = "authzOp";

    /*
     * Status of the authorization evaluation
     */
    public static final String TOKEN_AUTHZ_STATUS = "status";

    /**
     * Constant for the success status of the authorization evaluation.
     */
    public static final String AUTHZ_STATUS_SUCCESS = "statusSuccess";

    /**
     * Constructs an instance of a authorization token.
     * The token by default contains the following attributes: <br>
     * 
     * <pre>
     * 	"authzMgrInstName" - The authorization manager instance name.
     * 	"authzMgrImplName" - The authorization manager plugin name.
     * 	"authzTime" - The - The time of authorization.
     * </pre>
     * 
     * @param authzMgr The authorization manager that created this Token.
     */
    public AuthzToken(IAuthzManager authzMgr) {
        mAttrs = new Hashtable<String, Object>();
        mAttrs.put(TOKEN_AUTHZMGR_INST_NAME, authzMgr.getName());
        mAttrs.put(TOKEN_AUTHZMGR_IMPL_NAME, authzMgr.getImplName());
        mAttrs.put(TOKEN_AUTHZTIME, new Date());
    }

    /**
     * Get the value of an attribute in the AuthzToken
     * 
     * @param attrName The attribute name
     * @return The value of attrName if any.
     */
    public Object get(String attrName) {
        return mAttrs.get(attrName);
    }

    /**
     * Used by an Authorization manager to set an attribute and value
     * in the AuthzToken.
     * 
     * @param attrName The name of the attribute
     * @param value The value of the attribute to set.
     */
    public void set(String attrName, Object value) {
        mAttrs.put(attrName, value);
    }

    /**
     * Removes an attribute in the AuthzToken
     * 
     * @param attrName The name of the attribute to remove.
     */
    public void delete(String attrName) {
        mAttrs.remove(attrName);
    }

    /**
     * Enumerate all attribute names in the AuthzToken.
     * 
     * @return Enumeration of all attribute names in this AuthzToken.
     */
    public Enumeration<String> getElements() {
        return (mAttrs.keys());
    }

    /**
     * Enumerate all attribute values in the AuthzToken.
     * 
     * @return Enumeration of all attribute names in this AuthzToken.
     */
    public Enumeration<Object> getVals() {
        return (mAttrs.elements());
    }

    /**
     * Gets the name of the authorization manager instance that created
     * this token.
     * 
     * @return The name of the authorization manager instance that created
     *         this token.
     */
    public String getAuthzManagerInstName() {
        return ((String) mAttrs.get(TOKEN_AUTHZMGR_INST_NAME));
    }

    /**
     * Gets the plugin name of the authorization manager that created this
     * token.
     * 
     * @return The plugin name of the authorization manager that created this
     *         token.
     */
    public String getAuthzManagerImplName() {
        return ((String) mAttrs.get(TOKEN_AUTHZMGR_IMPL_NAME));
    }

    /**
     * Gets the time of authorization.
     * 
     * @return The time of authorization
     */
    public Date getAuthzTime() {
        return ((Date) mAttrs.get(TOKEN_AUTHZTIME));
    }
}
