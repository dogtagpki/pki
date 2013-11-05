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
package com.netscape.certsrv.usrgrp;

import java.security.cert.X509Certificate;
import java.util.Enumeration;

import netscape.ldap.LDAPException;

import com.netscape.certsrv.base.ISubsystem;

/**
 * This class defines low-level LDAP usr/grp management
 * usr/grp information is located remotely on another
 * LDAP server.
 *
 * @version $Revision$, $Date$
 */
public interface IUGSubsystem extends ISubsystem, IUsrGrp {

    /**
     * Constant for ID
     */
    public static final String ID = "usrgrp";

    /**
     * Constant for super administrators
     */
    public static final String SUPER_CERT_ADMINS = "Administrators";

    /**
     * Retrieves a user from LDAP
     *
     * @param userid the given user id
     * @exception EUsrGrpException thrown when failed to find the user
     */
    public IUser getUser(String userid) throws EUsrGrpException;

    /**
     * Searches for users that matches the filter.
     *
     * @param filter search filter for efficiency
     * @return list of users
     * @exception EUsrGrpException thrown when any internal error occurs
     */
    public Enumeration<IUser> listUsers(String filter) throws EUsrGrpException;

    /**
     * Adds the given user to the internal database
     *
     * @param identity the given user
     * @exception EUsrGrpException thrown when failed to add user to the group
     */
    public void addUser(IUser identity) throws EUsrGrpException;

    /**
     * Adds a user certificate to user
     *
     * @param identity user interface
     * @exception EUsrGrpException thrown when failed to add the user certificate to the given user
     */
    public void addUserCert(IUser identity) throws EUsrGrpException;

    /**
     * Add a certSubjectDN field to the user
     * @param identity
     * @throws EUsrGrpException
     * @throws LDAPException
     */
    public void addCertSubjectDN(IUser identity) throws EUsrGrpException;

    /**
     * Remove a certSubjectDN field from the user
     * @param identity
     * @throws EUsrGrpException
     */
    public void removeCertSubjectDN(IUser identity) throws EUsrGrpException;

    /**
     * Removes a user certificate for a user entry
     * given a user certificate DN (actually, a combination of version,
     * serialNumber, issuerDN, and SubjectDN), and it gets removed
     *
     * @param identity the given user whose user certificate is going to be
     *            be removed.
     * @exception EUsrGrpException thrown when failed to remove user certificate
     */
    public void removeUserCert(IUser identity) throws EUsrGrpException;

    /**
     * Removes identity.
     *
     * @param userid the given user id
     * @exception EUsrGrpException thrown when failed to remove user
     */
    public void removeUser(String userid) throws EUsrGrpException;

    /**
     * Modifies user attributes. Certs are handled separately
     *
     * @param identity the given identity which contains all the user
     *            attributes being modified
     * @exception EUsrGrpException thrown when modification failed
     */
    public void modifyUser(IUser identity) throws EUsrGrpException;

    /**
     * Finds groups that match the filter.
     *
     * @param filter the search filter
     * @return a list of groups that match the given search filter
     * @throws EUsrGrpException
     */
    public Enumeration<IGroup> findGroups(String filter) throws EUsrGrpException;

    /**
     * Finds groups that contain the user.
     *
     * @param userDn the user DN
     * @return a list of groups that contain the given user
     * @throws EUsrGrpException
     */
    public Enumeration<IGroup> findGroupsByUser(String userDn) throws EUsrGrpException;

    /**
     * Find a group for the given name
     *
     * @param name the given name
     * @return a group that matched the given name
     * @throws EUsrGrpException
     */
    public IGroup findGroup(String name) throws EUsrGrpException;

    /**
     * List groups. This method is more efficient than findGroups because
     * this method retrieves group names and description only. Each
     * retrieved group just contains group name and description.
     *
     * @param filter the search filter
     * @return a list of groups, each group just contains group name and
     *         its description.
     * @exception EUsrGrpException thrown when failed to list groups
     */
    public Enumeration<IGroup> listGroups(String filter) throws EUsrGrpException;

    /**
     * Retrieves a group from LDAP for the given group name
     *
     * @param name the given group name
     * @return a group interface
     */
    public IGroup getGroupFromName(String name);

    /**
     * Retrieves a group from LDAP for the given DN.
     *
     * @param DN the given DN
     * @return a group interface for the given DN.
     */
    public IGroup getGroup(String DN);

    /**
     * Checks if the given group exists.
     *
     * @param name the given group name
     * @return true if the given group exists in the internal database; otherwise false.
     */
    public boolean isGroupPresent(String name);

    /**
     * Checks if the given context is a member of the given group
     *
     * @param uid the given user id
     * @param name the given group name
     * @return true if the user with the given user id is a member of the given
     *         group
     */
    public boolean isMemberOf(String uid, String name);

    public boolean isMemberOf(IUser id, String name);

    /**
     * Adds a group of identities.
     *
     * @param group the given group
     * @exception EUsrGrpException thrown when failed to add group.
     */
    public void addGroup(IGroup group) throws EUsrGrpException;

    /**
     * Removes a group. Can't remove SUPER_CERT_ADMINS
     *
     * @param name the given group name
     * @exception EUsrGrpException thrown when the given group failed to remove
     */
    public void removeGroup(String name) throws EUsrGrpException;

    /**
     * Modifies a group.
     *
     * @param group the given group which contain all group attributes being
     *            modified.
     * @exception EUsrGrpException thrown when failed to modify group.
     */
    public void modifyGroup(IGroup group) throws EUsrGrpException;

    /**
     * Adds the user with the given id into the given group
     *
     * @param grp the given group
     * @param userid the given user id
     * @exception EUsrGrpException thrown when failed to add the user into
     *                the given group
     */
    public void addUserToGroup(IGroup grp, String userid)
            throws EUsrGrpException;

    /**
     * Removes the user with the given id from the given group
     *
     * @param grp the given group
     * @param userid the given user id
     * @exception EUsrGrpException thrown when failed to remove the user from
     *                the given group
     */
    public void removeUserFromGroup(IGroup grp, String userid)
            throws EUsrGrpException;

    /**
     * Create user with the given id.
     *
     * @param id the user with the given id.
     * @return a new user
     */
    public IUser createUser(String id);

    /**
     * Create group with the given id.
     *
     * @param id the group with the given id.
     * @return a new group
     */
    public IGroup createGroup(String id);

    /**
     * Get string representation of the given certificate
     *
     * @param cert given certificate
     * @return the string representation of the given certificate
     */
    public String getCertificateString(X509Certificate cert);

    /**
     * Searchs for identities that matches the filter.
     */
    public Enumeration<IUser> findUsers(String filter) throws EUsrGrpException;

    /**
     * Searchs for identities that matches the certificate locater
     * generated filter.
     *
     * @param filter search filter
     * @return an user
     * @exception EUsrGrpException thrown when failed to find user
     */
    public IUser findUsersByCert(String filter) throws EUsrGrpException;

    /**
     * Get user locator which does the mapping between the user and the certificate.
     *
     * @return CertUserLocator
     */
    public ICertUserLocator getCertUserLocator();
}
