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
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.user.UserResource;
import com.netscape.cmscore.apps.CMS;

/**
 * A class represents a user.
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class User {

    /**
     * Constant for userScope
     */
    public final static String ATTR_SCOPE = "userScope";

    /**
     * Constant for userName
     */
    public final static String ATTR_NAME = "userName";

    /**
     * Constant for userId
     */
    public final static String ATTR_ID = "userId";

    /**
     * Constant for userFullName
     */
    public final static String ATTR_FULLNAME = "userFullName";

    /**
     * Constant for userPassword
     */
    public final static String ATTR_PASSWORD = "userPassword";

    /**
     * Constant for userState
     */
    public final static String ATTR_STATE = "userstate";

    /**
     * Constant for userEmail
     */
    public final static String ATTR_EMAIL = "userEmail";

    /**
     * Constant for usertype
     */
    public final static String ATTR_USERTYPE = "usertype";

    /**
     * Constant for usertype
     */
    public final static String ATTR_TPS_PROFILES = "tpsProfiles";

    public final static String ATTR_X509_CERTIFICATES = "userCertificates";

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

        if (tpsProfiles == null) {
            this.tpsProfiles = null;
            return;
        }

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
    public User() {
    }

    @Deprecated
    public User(String userid) {
        mUserid = userid;
    }

    /**
     * Retrieves the name of this identity.
     *
     * @return user name
     * @deprecated
     */
    @JsonIgnore
    @Deprecated
    public String getName() {
        //		return mScope.getId() + "://" + mUserid;
        return mUserid;
    }

    /**
     * Retrieves user identifier.
     *
     * @return user id
     */
    @JsonProperty("id")
    public String getUserID() {
        return mUserid;
    }

    public void setUserID(String userID) {
        mUserid = userID;
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
            return getUserID();
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

    @JsonIgnore
    public Enumeration<String> getElements() {
        return mNames.elements();
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static User fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, User.class);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((mCertDN == null) ? 0 : mCertDN.hashCode());
        result = prime * result + ((mEmail == null) ? 0 : mEmail.hashCode());
        result = prime * result + ((mFullName == null) ? 0 : mFullName.hashCode());
        result = prime * result + ((mPassword == null) ? 0 : mPassword.hashCode());
        result = prime * result + ((mPhone == null) ? 0 : mPhone.hashCode());
        result = prime * result + ((mState == null) ? 0 : mState.hashCode());
        result = prime * result + ((mUserDN == null) ? 0 : mUserDN.hashCode());
        result = prime * result + ((mUserType == null) ? 0 : mUserType.hashCode());
        result = prime * result + ((mUserid == null) ? 0 : mUserid.hashCode());
        result = prime * result + Arrays.hashCode(mx509Certs);
        result = prime * result + ((tpsProfiles == null) ? 0 : tpsProfiles.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        User other = (User) obj;
        if (mCertDN == null) {
            if (other.mCertDN != null)
                return false;
        } else if (!mCertDN.equals(other.mCertDN))
            return false;
        if (mEmail == null) {
            if (other.mEmail != null)
                return false;
        } else if (!mEmail.equals(other.mEmail))
            return false;
        if (mFullName == null) {
            if (other.mFullName != null)
                return false;
        } else if (!mFullName.equals(other.mFullName))
            return false;
        if (mPassword == null) {
            if (other.mPassword != null)
                return false;
        } else if (!mPassword.equals(other.mPassword))
            return false;
        if (mPhone == null) {
            if (other.mPhone != null)
                return false;
        } else if (!mPhone.equals(other.mPhone))
            return false;
        if (mState == null) {
            if (other.mState != null)
                return false;
        } else if (!mState.equals(other.mState))
            return false;
        if (mUserDN == null) {
            if (other.mUserDN != null)
                return false;
        } else if (!mUserDN.equals(other.mUserDN))
            return false;
        if (mUserType == null) {
            if (other.mUserType != null)
                return false;
        } else if (!mUserType.equals(other.mUserType))
            return false;
        if (mUserid == null) {
            if (other.mUserid != null)
                return false;
        } else if (!mUserid.equals(other.mUserid))
            return false;
        if (!Arrays.equals(mx509Certs, other.mx509Certs))
            return false;
        if (tpsProfiles == null) {
            if (other.tpsProfiles != null)
                return false;
        } else if (!tpsProfiles.equals(other.tpsProfiles))
            return false;
        return true;
    }

    public static void main(String args[]) throws Exception {

        User before = new User();
        before.setUserID("testuser");
        before.setFullName("Test User");
        before.setEmail("testuser@example.com");

        String json = before.toJSON();
        System.out.println("Before: " + json);

        User after = User.fromJSON(json);
        System.out.println("After: " + after.toJSON());

        System.out.println(before.equals(after));
    }
}
