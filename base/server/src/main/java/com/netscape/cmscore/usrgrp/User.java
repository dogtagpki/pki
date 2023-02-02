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
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.user.UserResource;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPAttribute;

/**
 * A class represents a user.
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class User implements JSONSerializer {

    /**
     * Constant for userScope
     */
    public static final String ATTR_SCOPE = "userScope";

    /**
     * Constant for userName
     */
    public static final String ATTR_NAME = "userName";

    /**
     * Constant for userId
     */
    public static final String ATTR_ID = "userId";

    /**
     * Constant for userFullName
     */
    public static final String ATTR_FULLNAME = "userFullName";

    /**
     * Constant for userPassword
     */
    public static final String ATTR_PASSWORD = "userPassword";

    /**
     * Constant for userState
     */
    public static final String ATTR_STATE = "userstate";

    /**
     * Constant for userEmail
     */
    public static final String ATTR_EMAIL = "userEmail";

    /**
     * Constant for usertype
     */
    public static final String ATTR_USERTYPE = "usertype";

    /**
     * Constant for usertype
     */
    public static final String ATTR_TPS_PROFILES = "tpsProfiles";

    public static final String ATTR_X509_CERTIFICATES = "userCertificates";
    public static final String ATTRIBUTES = "attributes";
    public static final String CMS_BASE_INVALID_ATTRIBUTE = "CMS_BASE_INVALID_ATTRIBUTE";

    private String userid;
    private String userDN;
    private String fullName;
    private String password;
    private String email;
    private String phone;
    private String state;
    private String certDN;
    private String userType;
    private X509Certificate[] x509Certs;
    private List<String> tpsProfiles;
    private List<LDAPAttribute> attrs;

    private static final Set<String> names = Set.of(
        ATTR_NAME,
        ATTR_ID,
        ATTR_FULLNAME,
        ATTR_PASSWORD,
        ATTR_STATE,
        ATTR_EMAIL,
        ATTR_X509_CERTIFICATES,
        ATTR_USERTYPE,
        ATTR_TPS_PROFILES,
        ATTRIBUTES
    );

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
            List<String> list = new ArrayList<>();
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
        this.userid = userid;
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
        return userid;
    }

    /**
     * Retrieves user identifier.
     *
     * @return user id
     */
    @JsonProperty("id")
    public String getUserID() {
        return userid;
    }

    public void setUserID(String userID) {
        userid = userID;
    }

    /**
     * Retrieves user full name.
     *
     * @return user fullname
     */
    public String getFullName() {
        return fullName;
    }

    /**
     * Sets user full name.
     *
     * @param name the given full name
     */
    public void setFullName(String name) {
        this.fullName = name;
    }

    /**
     * Retrieves user LDAP DN
     *
     * @return user DN
     */
    public String getUserDN() {
        return userDN;
    }

    /**
     * Sets user LDAP DN.
     *
     * @param userdn the given user DN
     */
    public void setUserDN(String userdn) {
        this.userDN = userdn;
    }

    /**
     * Get user type
     *
     * @return user type.
     */
    public String getUserType() {
        return userType;
    }

    /**
     * Sets user type
     *
     * @param userType the given user type
     */
    public void setUserType(String userType) {
        this.userType = userType;
    }

    /**
     * Retrieves user password.
     *
     * @return user password
     */
    public String getPassword() {
        return password;
    }

    /**
     * Sets user password.
     *
     * @param password the given password
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * Gets user email address.
     *
     * @return email address
     */
    public String getEmail() {
        return email;
    }

    /**
     * Sets user email address.
     *
     * @param email the given email address
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     * Retrieves user phonenumber.
     *
     * @return user phonenumber
     */
    public String getPhone() {
        return phone;
    }

    /**
     * Retrieves user state
     *
     * @return user state
     */
    public String getState() {
        return state;
    }

    /**
     * Sets user phonenumber
     *
     * @param phone user phonenumber
     */
    public void setPhone(String phone) {
        this.phone = phone;
    }

    /**
     * Sets user state
     *
     * @param state the given user state
     */
    public void setState(String state) {
        this.state = state;
    }

    /**
     * Gets list of certificates from this user
     *
     * @return list of certificates
     */
    public X509Certificate[] getX509Certificates() {
        return x509Certs;
    }

    /**
     * Sets list of certificates in this user
     *
     * @param certs list of certificates
     */
    public void setX509Certificates(X509Certificate[] certs) {
        this.x509Certs = certs;
    }

    /**
     * Get certificate DN
     *
     * @return certificate DN
     */
    public String getCertDN() {
        return certDN;
    }

    /**
     * Set certificate DN
     *
     * @param dn the given DN
     */
    public void setCertDN(String dn) {
        this.certDN = dn;
    }

    public List<LDAPAttribute> getAttributes() {
        return attrs;
    }

    public void setAttributes(List<LDAPAttribute> attributes) {
        this.attrs = attributes;
    }

    @SuppressWarnings("unchecked")
    public void set(String name, Object object) throws EBaseException {
        if (name.equals(ATTR_NAME)) {
            throw new EBaseException(CMS.getUserMessage(CMS_BASE_INVALID_ATTRIBUTE, name));
        } else if (name.equals(ATTR_ID)) {
            throw new EBaseException(CMS.getUserMessage(CMS_BASE_INVALID_ATTRIBUTE, name));
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
        } else if (name.equals(ATTRIBUTES)) {
            setAttributes((List<LDAPAttribute>) object);
        }  else {
            throw new EBaseException(CMS.getUserMessage(CMS_BASE_INVALID_ATTRIBUTE, name));
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
        } else if (name.equals(ATTRIBUTES)) {
            return getAttributes();
        } else {
            throw new EBaseException(CMS.getUserMessage(CMS_BASE_INVALID_ATTRIBUTE, name));
        }
    }

    public void delete(String name) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage(CMS_BASE_INVALID_ATTRIBUTE, name));
    }

    @JsonIgnore
    public Enumeration<String> getElements() {
        return Collections.enumeration(names);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(x509Certs);
        result = prime * result + Objects.hash(attrs, certDN, email, fullName, password, phone, state,
                userDN, userType, userid, tpsProfiles);
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
        return Objects.equals(attrs, other.attrs) && Objects.equals(certDN, other.certDN)
                && Objects.equals(email, other.email) && Objects.equals(fullName, other.fullName)
                && Objects.equals(password, other.password) && Objects.equals(phone, other.phone)
                && Objects.equals(state, other.state) && Objects.equals(userDN, other.userDN)
                && Objects.equals(userType, other.userType) && Objects.equals(userid, other.userid)
                && Arrays.equals(x509Certs, other.x509Certs) && Objects.equals(tpsProfiles, other.tpsProfiles);
    }

    public static void main(String[] args) throws Exception {

        User before = new User();
        before.setUserID("testuser");
        before.setFullName("Test User");
        before.setEmail("testuser@example.com");

        String json = before.toJSON();
        System.out.println("Before: " + json);

        User after = JSONSerializer.fromJSON(json, User.class);
        System.out.println("After: " + after.toJSON());

        System.out.println(before.equals(after));
    }
}
