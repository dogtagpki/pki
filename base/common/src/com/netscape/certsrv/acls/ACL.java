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

import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;

/**
 * A class represents an access control list (ACL). An ACL
 * is associated with an protected resources. The policy
 * enforcer can verify the ACLs with the current
 * context to see if the corresponding resource is accessible.
 * <P>
 * An <code>ACL</code> may contain one or more <code>ACLEntry</code>. However, in case of multiple <code>ACLEntry</code>
 * , a subject must pass ALL of the <code>ACLEntry</code> evaluation for permission to be granted
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class ACL implements IACL, java.io.Serializable {

    /**
    *
    */
    private static final long serialVersionUID = -1867465948611161868L;

    protected Vector<ACLEntry> entries = new Vector<ACLEntry>(); // ACL entries
    protected TreeSet<String> rights = null; // possible rights entries
    protected String name = null; // resource name
    protected String description = null; // resource description

    // exact resourceACLs strings on ldap server
    protected TreeSet<String> resourceACLs = new TreeSet<>();

    /**
     * Class constructor.
     * Constructs an access control list associated
     * with a resource name
     *
     * @param name resource name
     * @param rights applicable rights defined for this resource
     * @param resourceACLs the entire ACL specification. For example:
     *            "certServer.log.configuration:read,modify:
     *            allow (read,modify)
     *            group=\"Administrators\":
     *            Allow administrators to read and modify log
     *            configuration"
     */
    private ACL(
            String name,
            Collection<String> rights,
            String desc,
            String resourceACLs) {
        if (name == null)
            throw new IllegalArgumentException("ACL name cannot be null");
        this.name = name;
        if (rights != null) {
            this.rights = new TreeSet<>(rights);
        } else {
            this.rights = new TreeSet<>();
        }
        this.resourceACLs.add(resourceACLs);
        this.description = desc;
    }

    /** Merge the rules of the other ACL into this one.
     *
     * @throws IllegalArgumentException if the ACLs do not have the same name.
     */
    public void merge(ACL other) {
        if (!this.name.equals(other.name))
            throw new IllegalArgumentException("Cannot merge ACLs; names do not match.");

        this.rights.addAll(other.rights);
        this.entries.addAll(other.entries);
        this.resourceACLs.addAll(other.resourceACLs);
    }

    /**
     * Retrieves the name of the resource governed by
     * this access control.
     *
     * @return name of the resource
     */
    public String getName() {
        return name;
    }

    /**
     * Retrieve an iterable of strings that were used to produce this ACL.
     *
     * @return Iterable of formatted ACLs
     */
    public Iterable<String> getResourceACLs() {
        return resourceACLs;
    }

    /**
     * Retrieves the description of the resource governed by
     * this access control.
     *
     * @return Description of the protected resource
     */
    public String getDescription() {
        return description;
    }

    /**
     * Returns ACL entries.
     *
     * @return enumeration for the <code>ACLEntry</code> vector
     */
    public Enumeration<ACLEntry> entries() {
        return entries.elements();
    }

    /**
     * Returns the string reprsentation.
     *
     * @return the string representation of the ACL entries in the
     *         following format:
     *         <resource name>[<ACLEntry1>,<ACLEntry 2>,...<ACLEntry N>]
     */
    public String toString() {
        StringBuilder entries = new StringBuilder();
        Enumeration<ACLEntry> e = entries();

        for (; e.hasMoreElements();) {
            ACLEntry entry = e.nextElement();

            entries.append(entry);
            if (e.hasMoreElements())
                entries.append(",");
        }
        return getName() + "[" + entries + "]";
    }

    /**
     * Tells if the permission is one of the defined "rights"
     *
     * @param permission permission to be checked
     * @return true if it's one of the "rights"; false otherwise
     */
    public boolean checkRight(String permission) {
        return rights.contains(permission);
    }

    /**
     * Returns rights entries.
     *
     * @return enumeration of rights defined for this ACL
     */
    public Enumeration<String> rights() {
        return Collections.enumeration(rights);
    }

    /**
     * Parse ACL resource attributes
     *
     * @param resACLs same format as the resourceACLs attribute:
     *
     * <PRE>
     *     <resource name>:<permission1,permission2,...permissionn>:
     *     <allow|deny> (<subset of the permission set>) <evaluator expression>
     * </PRE>
     *
     * @exception EACLsException ACL related parsing errors for resACLs
     * @return an ACL instance built from the parsed resACLs
     */
    public static ACL parseACL(String resACLs) throws EACLsException {
        if (resACLs == null) {
            throw new EACLsException(CMS.getUserMessage("CMS_ACL_NULL_VALUE", "resACLs"));
        }

        ACL acl = null;
        Vector<String> rights = null;
        int idx1 = resACLs.indexOf(":");

        if (idx1 <= 0) {
            acl = new ACL(resACLs, rights, null /* desc */, resACLs);
        } else {
            // getting resource id
            String resource = resACLs.substring(0, idx1);

            if (resource == null) {
                String infoMsg = "resource not specified in resourceACLS attribute:" +
                        resACLs;

                String[] params = new String[2];

                params[0] = resACLs;
                params[1] = infoMsg;
                throw new EACLsException(CMS.getUserMessage("CMS_ACL_PARSING_ERROR", params));
            }

            // getting list of applicable rights
            String st = resACLs.substring(idx1 + 1);
            int idx2 = st.indexOf(":");
            String rightsString = null;

            if (idx2 != -1)
                rightsString = st.substring(0, idx2);
            else {
                String infoMsg =
                        "rights not specified in resourceACLS attribute:" + resACLs;
                String[] params = new String[2];

                params[0] = resACLs;
                params[1] = infoMsg;
                throw new EACLsException(CMS.getUserMessage("CMS_ACL_PARSING_ERROR", params));
            }

            if (rightsString != null) {
                rights = new Vector<String>();
                StringTokenizer rtok = new StringTokenizer(rightsString, ",");

                while (rtok.hasMoreTokens()) {
                    rights.addElement(rtok.nextToken());
                }
            }

            // search *backwards* for final instance of ':', to handle case
            // where acl expressions contain colon, e.g. in a group name.
            String stx = st.substring(idx2 + 1);
            int idx3 = stx.lastIndexOf(":");
            String aclStr = stx.substring(0, idx3);
            String desc = stx.substring(idx3 + 1);

            acl = new ACL(resource, rights, desc, resACLs);

            // getting list of acl entries
            if (aclStr != null) {
                StringTokenizer atok = new StringTokenizer(aclStr, ";");

                while (atok.hasMoreTokens()) {
                    String acs = atok.nextToken();

                    // construct ACL entry
                    ACLEntry entry = ACLEntry.parseACLEntry(acl, acs);

                    if (entry == null) {
                        String infoMsg = "parseACLEntry() call failed";
                        String[] params = new String[2];

                        params[0] = "ACLEntry = " + acs;
                        params[1] = infoMsg;
                        throw new EACLsException(CMS.getUserMessage("CMS_ACL_PARSING_ERROR", params));
                    }

                    entry.setACLEntryString(acs);
                    acl.entries.add(entry);
                }
            } else {
                // fine
                String infoMsg = "acls not specified in resourceACLS attribute:" +

                resACLs;

                String[] params = new String[2];

                params[0] = resACLs;
                params[1] = infoMsg;
                throw new EACLsException(CMS.getUserMessage("CMS_ACL_PARSING_ERROR", params));
            }
        }

        return (acl);
    }
}
