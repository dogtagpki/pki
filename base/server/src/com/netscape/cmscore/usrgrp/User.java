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
package com.netscape.cmscore.usrgrp;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IAttrSet;
import com.netscape.certsrv.user.UserResource;
import com.netscape.certsrv.usrgrp.IUserConstants;
import com.netscape.cmscore.apps.CMS;

/**
 * A class represents a user.
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class User implements IAttrSet, IUserConstants {

    /**
     *
     */
    private static final long serialVersionUID = -7407288327775546979L;
    public static final String ATTR_X509_CERTIFICATES = "userCertificates";

    private String mUserid = null;
    private String mUserDN = null;
    private String mFullName = null;
    private String mPassword = null;
    private String mEmail = null;
    private String mPhone = null;
    private String mState = null;
    private String mCertDN = null;
    private String mUserType = null;
    private X509Certificate mx509Certs[] = null;
    private List<String> tpsProfiles = null;

    private static final Vector<String> mNames = new Vector<String>();
    static {
        mNames.addElement(ATTR_NAME);
        mNames.addElement(ATTR_ID);
        mNames.addElement(ATTR_FULLNAME);
        mNames.addElement(ATTR_PASSWORD);
        mNames.addElement(ATTR_STATE);
        mNames.addElement(ATTR_EMAIL);
        // mNames.addElement(ATTR_PHONENUMBER);
        mNames.addElement(ATTR_X509_CERTIFICATES);
        mNames.addElement(ATTR_USERTYPE);
        mNames.addElement(ATTR_TPS_PROFILES);
    }

    /**
     * Get TPS profiles
     */
    public List<String> getTpsProfiles() {
        return tpsProfiles;
    }

    /**
     * Set TPS profiles
     * @param tpsProfiles
     */
    public void setTpsProfiles(List<String> tpsProfiles) {
        boolean setAll = false;
        for (String profile: tpsProfiles) {
            if (profile.equals(UserResource.ALL_PROFILES)) {
                setAll = true;
                break;
            }
        }
        if (!setAll) {
            this.tpsProfiles = tpsProfiles;
        } else {
            List<String> list = new ArrayList<String>();
            list.add(UserResource.ALL_PROFILES);
            this.tpsProfiles = list;
        }
    }

    /**
     * Constructs a user.
     */
    public User(String userid) {
        mUserid = userid;
    }

    /**
     * Retrieves the name of this identity.
     *
     * @return user name
     */
    public String getName() {
        //		return mScope.getId() + "://" + mUserid;
        return mUserid;
    }

    /**
     * Retrieves user identifier.
     *
     * @return user id
     */
    public String getUserID() {
        return mUserid;
    }

    /**
     * Retrieves user full name.
     *
     * @return user fullname
     */
    public String getFullName() {
        return mFullName;
    }

    /**
     * Sets user full name.
     *
     * @param name the given full name
     */
    public void setFullName(String name) {
        mFullName = name;
    }

    /**
     * Retrieves user LDAP DN
     *
     * @return user DN
     */
    public String getUserDN() {
        return mUserDN;
    }

    /**
     * Sets user LDAP DN.
     *
     * @param userdn the given user DN
     */
    public void setUserDN(String userdn) {
        mUserDN = userdn;
    }

    /**
     * Get user type
     *
     * @return user type.
     */
    public String getUserType() {
        return mUserType;
    }

    /**
     * Sets user type
     *
     * @param userType the given user type
     */
    public void setUserType(String userType) {
        mUserType = userType;
    }

    /**
     * Retrieves user password.
     *
     * @return user password
     */
    public String getPassword() {
        return mPassword;
    }

    /**
     * Sets user password.
     *
     * @param p the given password
     */
    public void setPassword(String password) {
        mPassword = password;
    }

    /**
     * Gets user email address.
     *
     * @return email address
     */
    public String getEmail() {
        return mEmail;
    }

    /**
     * Sets user email address.
     *
     * @param email the given email address
     */
    public void setEmail(String email) {
        mEmail = email;
    }

    /**
     * Retrieves user phonenumber.
     *
     * @return user phonenumber
     */
    public String getPhone() {
        return mPhone;
    }

    /**
     * Retrieves user state
     *
     * @return user state
     */
    public String getState() {
        return mState;
    }

    /**
     * Sets user phonenumber
     *
     * @param p user phonenumber
     */
    public void setPhone(String phone) {
        mPhone = phone;
    }

    /**
     * Sets user state
     *
     * @param p the given user state
     */
    public void setState(String state) {
        mState = state;
    }

    /**
     * Gets list of certificates from this user
     *
     * @return list of certificates
     */
    public X509Certificate[] getX509Certificates() {
        return mx509Certs;
    }

    /**
     * Sets list of certificates in this user
     *
     * @param certs list of certificates
     */
    public void setX509Certificates(X509Certificate certs[]) {
        mx509Certs = certs;
    }

    /**
     * Get certificate DN
     *
     * @return certificate DN
     */
    public String getCertDN() {
        return mCertDN;
    }

    /**
     * Set certificate DN
     *
     * @param userdn the given DN
     */
    public void setCertDN(String dn) {
        mCertDN = dn;
    }

    @SuppressWarnings("unchecked")
    public void set(String name, Object object) throws EBaseException {
        if (name.equals(ATTR_NAME)) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        } else if (name.equals(ATTR_ID)) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        } else if (name.equals(ATTR_FULLNAME)) {
            setFullName((String) object);
        } else if (name.equals(ATTR_STATE)) {
            setState((String) object);
        } else if (name.equals(ATTR_PASSWORD)) {
            setPassword((String) object);
        } else if (name.equals(ATTR_X509_CERTIFICATES)) {
            setX509Certificates((X509Certificate[]) object);
        } else if (name.equals(ATTR_USERTYPE)) {
            setUserType((String) object);
        } else if (name.equals(ATTR_TPS_PROFILES)) {
            setTpsProfiles((List<String>) object);
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        }
    }

    public Object get(String name) throws EBaseException {
        if (name.equals(ATTR_NAME)) {
            return getName();
        } else if (name.equals(ATTR_ID)) {
            return getUserID();
        } else if (name.equals(ATTR_STATE)) {
            return getState();
        } else if (name.equals(ATTR_FULLNAME)) {
            return getFullName();
        } else if (name.equals(ATTR_PASSWORD)) {
            return getPassword();
        } else if (name.equals(ATTR_X509_CERTIFICATES)) {
            return getX509Certificates();
        } else if (name.equals(ATTR_USERTYPE)) {
            return getUserType();
        } else if (name.equals(ATTR_TPS_PROFILES)) {
            return getTpsProfiles();
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        }
    }

    public void delete(String name) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
    }

    public Enumeration<String> getElements() {
        return mNames.elements();
    }
}
