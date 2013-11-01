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
package com.netscape.certsrv.acls;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;

/**
 * A class represents an ACI entry of an access control list.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class ACLEntry implements IACLEntry, java.io.Serializable {
    /**
    *
    */
    private static final long serialVersionUID = 422656406529200393L;

    protected Hashtable<String, String> mPerms = new Hashtable<String, String>();
    protected String expressions = null;
    protected boolean negative = false;
    protected String aclEntryString = null;

    /**
     * Class Constructor
     */
    public ACLEntry() {
    }

    /**
     * Checks if this ACL entry is set to negative.
     *
     * @return true if this ACL entry expression is for "deny";
     *         false if this ACL entry expression is for "allow"
     */
    public boolean isNegative() {
        return negative;
    }

    /**
     * Sets this ACL entry negative. This ACL entry expression is for "deny".
     */
    public void setNegative() {
        negative = true;
    }

    /**
     * Sets the ACL entry string
     *
     * @param s string in the following format:
     *
     *            <PRE>
     *   allow|deny (right[,right...]) attribute_expression
     * </PRE>
     */
    public void setACLEntryString(String s) {
        aclEntryString = s;
    }

    /**
     * Gets the ACL Entry String
     *
     * @return ACL Entry string in the following format:
     *
     *         <PRE>
     *   allow|deny (right[,right...]) attribute_expression
     * </PRE>
     */
    public String getACLEntryString() {
        return aclEntryString;
    }

    /**
     * Adds permission to this entry. Permission must be one of the
     * "rights" defined for each protected resource in its ACL
     *
     * @param acl the acl instance that this aclEntry is associated with
     * @param permission one of the "rights" defined for each
     *            protected resource in its ACL
     */
    public void addPermission(IACL acl, String permission) {
        if (acl.checkRight(permission) == true) {
            mPerms.put(permission, permission);
        } else {
            // not a valid right...log it later
        }
    }

    /**
     * Returns a list of permissions associated with
     * this entry.
     *
     * @return a list of permissions for this ACL entry
     */
    public Enumeration<String> permissions() {
        return mPerms.elements();
    }

    /**
     * Sets the expression associated with this entry.
     *
     * @param expressions the evaluator expressions. For example,
     *            group="Administrators"
     */
    public void setAttributeExpressions(String expressions) {
        this.expressions = expressions;
    }

    /**
     * Retrieves the expression associated with this entry.
     *
     * @return the evaluator expressions. For example,
     *         group="Administrators"
     */
    public String getAttributeExpressions() {
        return expressions;
    }

    /**
     * Checks to see if this <code>ACLEntry</code> contains a
     * particular permission
     *
     * @param permission one of the "rights" defined for each
     *            protected resource in its ACL
     * @return true if permission contained in the permission list
     *         for this <code>ACLEntry</code>; false otherwise.
     */
    public boolean containPermission(String permission) {
        return (mPerms.get(permission) != null);
    }

    /**
     * Checks if this entry has the given permission.
     *
     * @param permission one of the "rights" defined for each
     *            protected resource in its ACL
     * @return true if the permission is allowed; false if the
     *         permission is denied. If a permission is not
     *         recognized by this ACL, it is considered denied
     */
    public boolean checkPermission(String permission) {
        // default - if we dont know about the requested permission,
        //           don't grant permission
        if (mPerms.get(permission) == null)
            return false;
        if (isNegative()) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * Parse string in the following format:
     *
     * <PRE>
     *   allow|deny (right[,right...]) attribute_expression
     * </PRE>
     *
     * into an instance of the <code>ACLEntry</code> class
     *
     * @param acl the acl instance associated with this aclentry
     * @param aclEntryString aclEntryString in the specified format
     * @return an instance of the <code>ACLEntry</code> class
     */
    public static ACLEntry parseACLEntry(IACL acl, String aclEntryString) {
        if (aclEntryString == null) {
            return null;
        }

        String te = aclEntryString.trim();

        // locate first space
        int i = te.indexOf(' ');
        // prefix should be "allowed" or "deny"
        String prefix = te.substring(0, i);
        String suffix = te.substring(i + 1).trim();
        ACLEntry entry = new ACLEntry();

        if (prefix.equals("allow")) {
            // do nothing
        } else if (prefix.equals("deny")) {
            entry.setNegative();
        } else {
            return null;
        }
        // locate the second space
        i = suffix.indexOf(' ');
        // this prefix should be rights list, delimited by ","
        prefix = suffix.substring(1, i - 1);
        // the suffix is the rest, which is the "expressions"
        suffix = suffix.substring(i + 1).trim();

        StringTokenizer st = new StringTokenizer(prefix, ",");

        for (; st.hasMoreTokens();) {
            entry.addPermission(acl, st.nextToken());
        }
        entry.setAttributeExpressions(suffix);
        return entry;
    }

    /**
     * Returns the string representation of this ACLEntry
     *
     * @return string representation of this ACLEntry
     */
    public String toString() {
        StringBuffer entry = new StringBuffer();

        if (isNegative()) {
            entry.append("deny (");
        } else {
            entry.append("allow (");
        }
        Enumeration<String> e = permissions();

        for (; e.hasMoreElements();) {
            String p = e.nextElement();

            entry.append(p);
            if (e.hasMoreElements())
                entry.append(",");
        }
        entry.append(") " + getAttributeExpressions());
        return entry.toString();
    }
}
