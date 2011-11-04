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
package netscape.security.acl;

import java.security.Principal;
import java.security.acl.Acl;
import java.security.acl.AclEntry;
import java.security.acl.Group;
import java.security.acl.NotOwnerException;
import java.security.acl.Permission;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.NoSuchElementException;
import java.util.Vector;

/**
 * An Access Control List (ACL) is encapsulated by this class.
 * @author 	Satish Dharmaraj
 */
public class AclImpl extends OwnerImpl implements Acl {
    //
    // Maintain four tables. one each for positive and negative
    // ACLs. One each depending on whether the entity is a group
    // or principal.
    //
    private Hashtable allowedUsersTable = new Hashtable(23);
    private Hashtable allowedGroupsTable = new Hashtable(23);
    private Hashtable deniedUsersTable = new Hashtable(23);
    private Hashtable deniedGroupsTable = new Hashtable(23);
    private String aclName = null;
    private Vector zeroSet = new Vector(1,1);


    /**
     * Constructor for creating an empty ACL.
     */
    public AclImpl(Principal owner, String name) {
	super(owner);
	try {
	    setName(owner, name);
	} catch (Exception e) {}
    } 

    /**
     * Sets the name of the ACL.
     * @param caller the principal who is invoking this method. 
     * @param name the name of the ACL.
     * @exception NotOwnerException if the caller principal is
     * not on the owners list of the Acl.
     */
    public void setName(Principal caller, String name)
      throws NotOwnerException
    {
	if (!isOwner(caller))
	    throw new NotOwnerException();

	aclName = name;
    }

    /**
     * Returns the name of the ACL. 
     * @return the name of the ACL.
     */
    public String getName() {
	return aclName;
    }

    /**
     * Adds an ACL entry to this ACL. An entry associates a 
     * group or a principal with a set of permissions. Each 
     * user or group can have one positive ACL entry and one 
     * negative ACL entry. If there is one of the type (negative 
     * or positive) already in the table, a false value is returned.
     * The caller principal must be a part of the owners list of 
     * the ACL in order to invoke this method.
     * @param caller the principal who is invoking this method. 
     * @param entry the ACL entry that must be added to the ACL. 
     * @return true on success, false if the entry is already present.
     * @exception NotOwnerException if the caller principal 
     * is not on the owners list of the Acl.
     */
    public synchronized boolean addEntry(Principal caller, AclEntry entry) 
      throws NotOwnerException
    {
	if (!isOwner(caller))
	    throw new NotOwnerException();

	Hashtable aclTable = findTable(entry); 
	Principal key = entry.getPrincipal();

	if (aclTable.get(key) != null)
	    return false;

	aclTable.put(key, entry);
	return true;
    }

    /**
     * Removes an ACL entry from this ACL.
     * The caller principal must be a part of the owners list of the ACL 
     * in order to invoke this method.
     * @param caller the principal who is invoking this method. 
     * @param entry the ACL entry that must be removed from the ACL.
     * @return true on success, false if the entry is not part of the ACL.
     * @exception NotOwnerException if the caller principal is not
     * the owners list of the Acl.
     */
    public synchronized boolean removeEntry(Principal caller, AclEntry entry) 
      throws NotOwnerException
    {
	if (!isOwner(caller))
	    throw new NotOwnerException();

	Hashtable aclTable = findTable(entry);
	Object key = entry.getPrincipal();

	Object o = aclTable.remove(key);
	return (o != null);
    }
    /**
     * This method returns the set of allowed permissions for the 
     * specified principal. This set of allowed permissions is calculated
     * as follows:
     *
     * If there is no entry for a group or a principal an empty permission 
     * set is assumed.
     * 
     * The group positive permission set is the union of all 
     * the positive permissions of each group that the individual belongs to.
     * The group negative permission set is the union of all 
     * the negative permissions of each group that the individual belongs to.
     * If there is a specific permission that occurs in both 
     * the postive permission set and the negative permission set, 
     * it is removed from both. The group positive and negatoive permission 
     * sets are calculated.
     *
     * The individial positive permission set and the individual negative 
     * permission set is then calculated. Again abscence of an entry means
     * the empty set.
     *
     * The set of permissions granted to the principal is then calculated using
     * the simple rule: Individual permissions always override the Group permissions. 
     * Specifically, individual negative permission set (specific 
     * denial of permissions) overrides the group positive permission set.
     * And the individual positive permission set override the group negative 
     * permission set. 
     *
     * @param user the principal for which the ACL entry is returned.
     * @return The resulting permission set that the principal is allowed. 
     */
    public synchronized Enumeration getPermissions(Principal user) {

	Enumeration individualPositive;
	Enumeration individualNegative;
	Enumeration groupPositive;
	Enumeration groupNegative;

	//
	// canonicalize the sets. That is remove common permissions from
	// positive and negative sets.
	//
	groupPositive = subtract(getGroupPositive(user), getGroupNegative(user));
	groupNegative  = subtract(getGroupNegative(user), getGroupPositive(user));
	individualPositive = subtract(getIndividualPositive(user), getIndividualNegative(user));
	individualNegative = subtract(getIndividualNegative(user), getIndividualPositive(user));

	//
	// net positive permissions is individual positive permissions
	// plus (group positive - individual negative).
	//
	Enumeration temp1 = subtract(groupPositive, individualNegative);
	Enumeration netPositive = union(individualPositive, temp1);

	// recalculate the enumeration since we lost it in performing the
	// subtraction
	//
	individualPositive = subtract(getIndividualPositive(user), getIndividualNegative(user));
	individualNegative = subtract(getIndividualNegative(user), getIndividualPositive(user));

	//
	// net negative permissions is individual negative permissions
	// plus (group negative - individual positive).
	//
	temp1 = subtract(groupNegative, individualPositive);
	Enumeration netNegative = union(individualNegative, temp1);

	return subtract(netPositive, netNegative);
    }

    /**
     * This method checks whether or not the specified principal
     * has the required permission. If permission is denied 
     * permission false is returned, a true value is returned otherwise.
     * This method does not authenticate the principal. It presumes that 
     * the principal is a valid authenticated principal.
     * @param principal the name of the authenticated principal
     * @param permission the permission that the principal must have.
     * @return true of the principal has the permission desired, false 
     * otherwise.
     */
    public boolean checkPermission(Principal principal, Permission permission) 
    {
	Enumeration permSet = getPermissions(principal);
	while (permSet.hasMoreElements()) {
	    Permission p = (Permission) permSet.nextElement();
	    if (p.equals(permission)) 
	      return true;
	}
	return false;
    }

    /**
     * returns an enumeration of the entries in this ACL.
     */
    public synchronized Enumeration entries() {
	return new AclEnumerator(this, 
				 allowedUsersTable, allowedGroupsTable, 
				 deniedUsersTable, deniedGroupsTable);
    }

    /**
     * return a stringified version of the 
     * ACL.
     */
    public String toString() {
	StringBuffer sb = new StringBuffer();
	Enumeration entries = entries();
	while (entries.hasMoreElements()) {
	    AclEntry entry = (AclEntry) entries.nextElement();
	    sb.append(entry.toString().trim());
	    sb.append("\n");
	}

	return sb.toString();
    }

    //
    // Find the table that this entry belongs to. There are 4 
    // tables that are maintained. One each for postive and 
    // negative ACLs and one each for groups and users. 
    // This method figures out which 
    // table is the one that this AclEntry belongs to.
    //
    private Hashtable findTable(AclEntry entry) {
	Hashtable aclTable = null;

	Principal p = entry.getPrincipal();
	if (p instanceof Group) {
	    if (entry.isNegative()) 
		aclTable = deniedGroupsTable;
	    else 
		aclTable = allowedGroupsTable;
	} else {
	    if (entry.isNegative()) 
		aclTable = deniedUsersTable;
	    else 
		aclTable = allowedUsersTable;
	}
	return aclTable;
    }

    //
    // returns the set e1 U e2.
    //
    private static Enumeration union(Enumeration e1, Enumeration e2) {
	Vector v = new Vector(20, 20);

	while (e1.hasMoreElements()) 
	    v.addElement(e1.nextElement());

	while (e2.hasMoreElements()) {
	    Object o = e2.nextElement();
	    if (!v.contains(o))
		v.addElement(o);
	}
	
	return v.elements();
    }

    //
    // returns the set e1 - e2.
    //
    private Enumeration subtract(Enumeration e1, Enumeration e2) {
	Vector v = new Vector (20, 20);

	while (e1.hasMoreElements()) 
	    v.addElement(e1.nextElement());

	while (e2.hasMoreElements()) {
	    Object o = e2.nextElement();
	    if (v.contains(o))
		v.removeElement(o);
	}
	
	return v.elements();
    }

    private Enumeration getGroupPositive(Principal user) {
	Enumeration groupPositive = zeroSet.elements();
	Enumeration e = allowedGroupsTable.keys();
	while (e.hasMoreElements()) {
	    Group g = (Group) e.nextElement();
	    if (g.isMember(user)) {
		AclEntry ae = (AclEntry) allowedGroupsTable.get(g);
		groupPositive = union(ae.permissions(), groupPositive);
	    }
	}
	return groupPositive;
    }

    private Enumeration getGroupNegative(Principal user) {
	Enumeration groupNegative = zeroSet.elements();
	Enumeration e = deniedGroupsTable.keys();
	while (e.hasMoreElements()) {
	    Group g = (Group) e.nextElement();
	    if (g.isMember(user)) {
		AclEntry ae = (AclEntry) deniedGroupsTable.get(g);
		groupNegative = union(ae.permissions(), groupNegative);
	    }
	} 
	return groupNegative;
    }

    private Enumeration getIndividualPositive(Principal user) {
	Enumeration individualPositive = zeroSet.elements();
	AclEntry ae = (AclEntry) allowedUsersTable.get(user);
	if (ae != null)
	    individualPositive = ae.permissions();
	return individualPositive;
    }

    private Enumeration getIndividualNegative(Principal user) {
	Enumeration individualNegative = zeroSet.elements();
	AclEntry ae  = (AclEntry) deniedUsersTable.get(user);
	if (ae != null)
	    individualNegative = ae.permissions();
	return individualNegative;
    }
}

final class AclEnumerator implements Enumeration {
    Acl acl;
    Enumeration u1, u2, g1, g2;

    AclEnumerator(Acl acl, Hashtable u1, Hashtable g1, 
		  Hashtable u2, Hashtable g2) {
	this.acl = acl;
	this.u1 = u1.elements();
	this.u2 = u2.elements();
	this.g1 = g1.elements();
	this.g2 = g2.elements();
    }

    public boolean hasMoreElements() {
	return (u1.hasMoreElements() ||
		u2.hasMoreElements() ||
		g1.hasMoreElements() ||
		g2.hasMoreElements());
    }

    public Object nextElement() 
    {
	Object o;
	synchronized (acl) {
	    if (u1.hasMoreElements())
		return u1.nextElement();
	    if (u2.hasMoreElements())
		return u2.nextElement();
	    if (g1.hasMoreElements())
		return g1.nextElement();
	    if (g2.hasMoreElements())
		return g2.nextElement();
	}
	throw new NoSuchElementException("Acl Enumerator");
    }
}
