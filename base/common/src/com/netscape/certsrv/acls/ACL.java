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
import java.util.Vector;

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
    protected Vector<String> rights = null; // possible rights entries
    protected String resourceACLs = null; // exact resourceACLs string on ldap server
    protected String name = null; // resource name
    protected String description = null; // resource description

    /**
     * Class constructor.
     */
    public ACL() {
    }

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
    public ACL(String name, Vector<String> rights, String resourceACLs) {
        setName(name);
        if (rights != null) {
            this.rights = rights;
        } else {
            this.rights = new Vector<String>();
        }
        this.resourceACLs = resourceACLs;

    }

    /**
     * Sets the name of the resource governed by this
     * access control.
     *
     * @param name name of the resource
     */
    public void setName(String name) {
        this.name = name;
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
     * Retrieves the exact string of the resourceACLs
     *
     * @return resource's acl
     */
    public String getResourceACLs() {
        return resourceACLs;
    }

    /**
     * Sets the description of the resource governed by this
     * access control.
     *
     * @param description Description of the protected resource
     */
    public void setDescription(String description) {
        this.description = description;
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
     * Adds an ACL entry to this list.
     *
     * @param entry the <code>ACLEntry</code> to be added to this resource
     */
    public void addEntry(ACLEntry entry) {
        entries.addElement(entry);
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
     * Adds an rights entry to this list.
     *
     * @param right The right to be added for this ACL
     */
    public void addRight(String right) {
        rights.addElement(right);
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
        return rights.elements();
    }
}
