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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;

import org.apache.commons.lang3.StringUtils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.LDAPExceptionConverter;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.password.IPasswordStore;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPDN;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

/**
 * This class defines low-level LDAP usr/grp management
 * usr/grp information is located remotely on another
 * LDAP server.
 *
 * @author thomask
 * @author cfu
 * @version $Revision$, $Date$
 */
public class UGSubsystem {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UGSubsystem.class);

    public static final String SUPER_CERT_ADMINS = "Administrators";

    protected static final String OBJECTCLASS_ATTR = "objectclass";
    protected static final String MEMBER_ATTR = "uniquemember";
    protected static final String GROUP_ATTR_VALUE = "groupofuniquenames";

    protected static final String LDAP_ATTR_USER_CERT_STRING = "description";
    protected static final String LDAP_ATTR_CERTDN = "seeAlso";
    protected static final String LDAP_ATTR_USER_CERT = "userCertificate";
    protected static final String LDAP_ATTR_PROFILE_ID = "profileID";

    protected transient LdapBoundConnFactory mLdapConnFactory = null;
    protected String mBaseDN = null;

    /**
     * Constructs LDAP based usr/grp management
     */
    public UGSubsystem() {
    }

    public void init(
            PKISocketConfig socketConfig,
            UGSubsystemConfig config,
            IPasswordStore passwordStore) throws Exception {

        logger.info("UGSubsystem: Initializing user/group subsystem");

        LDAPConfig ldapConfig = config.getLDAPConfig();
        mBaseDN = ldapConfig.getBaseDN();

        mLdapConnFactory = new LdapBoundConnFactory("UGSubsystem");
        mLdapConnFactory.init(socketConfig, ldapConfig, passwordStore);
    }

    /**
     * Disconnects usr/grp manager from the LDAP
     */
    public void shutdown() {
        try {
            if (mLdapConnFactory != null) {
                mLdapConnFactory.reset();
            }
        } catch (ELdapException e) {
            logger.warn("Unable to shutdown connection: " + e.getMessage(), e);
        }
    }

    public User createUser(String id) {
        User user = new User();
        user.setUserID(id);
        return user;
    }

    public Group createGroup(String id) {
        return new Group(id);
    }

    /**
     * Retrieves a user from LDAP
     */
    public User getUser(String userID) throws EUsrGrpException {

        if (userID == null) {
            return null;
        }

        String userDN;

        if (userID.indexOf('=') < 0) { // user ID is not a DN
            userDN = getUserDN(userID);

        } else { // user ID is a DN
            // TODO: use a separate method for user ID and DN
            userDN = userID;
        }

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();

            logger.info("UGSubsystem: retrieving user " + userDN);

            LDAPSearchResults res = ldapconn.search(
                    userDN,
                    LDAPv2.SCOPE_BASE,
                    "(objectclass=*)",
                    null,
                    false);

            // throw EUsrGrpException if result is empty
            Enumeration<User> e = buildUsers(res);

            // user found
            return e.nextElement();

        } catch (ELdapException e) {
            throw new EUsrGrpException("Unable to retrieve user: " + userID + ": " + e.getMessage(), e);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                logger.info("UGSubsystem: user not found: " + userID);
                return null;

            } else {
                throw new EUsrGrpException("Unable to retrieve user: " + userID + ": " + e.getMessage(), e);
            }

        } finally {
            if (ldapconn != null) returnConn(ldapconn);
        }
    }

    /**
     * Locates a user by certificate.
     */
    public User findUser(X509Certificate cert) throws EUsrGrpException {
        if (cert == null) {
            return null;
        }

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            String filter = LDAP_ATTR_USER_CERT_STRING + "=" + LDAPUtil.escapeFilter(getCertificateString(cert));
            LDAPSearchResults res =
                    ldapconn.search(getUserBaseDN(),
                            LDAPConnection.SCOPE_SUB, filter, null, false);
            Enumeration<User> e = buildUsers(res);

            return e.nextElement();

        } catch (LDAPException e) {
            logger.warn("Unable to find user: " + e.getMessage(), e);

        } catch (ELdapException e) {
            logger.warn("Unable to connect to internal database: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
        return null;
    }

    /**
     * Searchs for identities that matches the certificate locater
     * generated filter.
     */
    public User findUsersByCert(String filter) throws EUsrGrpException {
        if (filter == null) {
            return null;
        }

        // To handle \ in the issuer DN or subject DN
        // (see also RFC 2254, and bug #348303
        int hasSlash = filter.indexOf('\\');

        if (hasSlash != -1) {
            String up = filter;
            StringBuffer stripped = new StringBuffer();

            hasSlash = up.indexOf('\\');
            while (hasSlash != -1) {
                stripped.append(up.substring(0, hasSlash) + "\\5c");

                up = up.substring(hasSlash + 1);
                hasSlash = up.indexOf('\\');
            }
            filter = stripped.toString() + up;
        }

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            LDAPSearchResults res = ldapconn.search(getUserBaseDN(),
                    LDAPv2.SCOPE_SUB, "(" + filter + ")",
                    null, false);

            Enumeration<User> e = buildUsers(res);

            return e.nextElement();

        } catch (LDAPException e) {
            logger.warn("Unable to find user by certificate: " + e.getMessage(), e);

        } catch (ELdapException e) {
            logger.warn("Unable to find user by certificate: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }

        return null;
    }

    /**
     * Searchs for identities that matches the filter.
     */
    public Enumeration<User> findUsers(String filter) throws EUsrGrpException {

        String ldapFilter;
        if (StringUtils.isEmpty(filter)) {
            ldapFilter = "(uid=*)";

        } else {
            filter = LDAPUtil.escapeFilter(filter);
            ldapFilter = "(|(uid=*" + filter + "*)(cn=*" + filter + "*)(mail=*" + filter + "*))";
        }

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();

            // use one-level search to search users in flat tree
            LDAPSearchResults res = ldapconn.search(
                    getUserBaseDN(),
                    LDAPv2.SCOPE_ONE,
                    ldapFilter,
                    null,
                    false);

            // throw EUsrGrpException if result is empty
            Enumeration<User> e = buildUsers(res);

            return e;

        } catch (LDAPException e) {
            logger.warn("Unable to find user: " + e.getMessage(), e);

        } catch (ELdapException e) {
            logger.warn("Unable to find user: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }

        return null;
    }

    /**
     * Searchs for identities that matches the filter.
     * retrieves uid only, for efficiency of user listing
     */
    public Enumeration<User> listUsers(String filter) throws EUsrGrpException {
        if (filter == null) {
            return null;
        }

        LDAPConnection ldapconn = null;

        try {
            String attrs[] = new String[2];

            attrs[0] = "uid";
            attrs[1] = "cn";

            ldapconn = getConn();
            LDAPSearchConstraints cons = new LDAPSearchConstraints();

            cons.setMaxResults(0);
            LDAPSearchResults res = ldapconn.search(getUserBaseDN(),
                    LDAPv2.SCOPE_SUB, "(uid=" + filter + ")", attrs, false, cons);
            Enumeration<User> e = lbuildUsers(res);

            return e;

        } catch (LDAPException e) {
            logger.warn("Unable to list users: " + e.getMessage(), e);

        } catch (Exception e) {
            throw new EUsrGrpException("Unable to list users: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }

        return null;
    }

    protected Enumeration<User> lbuildUsers(LDAPSearchResults res) throws
            EUsrGrpException {
        Vector<User> v = new Vector<User>();

        while (res.hasMoreElements()) {
            LDAPEntry entry = (LDAPEntry) res.nextElement();
            User user = lbuildUser(entry);

            v.addElement(user);
        }
        return v.elements();
    }

    protected Enumeration<User> buildUsers(LDAPSearchResults res) throws
            EUsrGrpException {
        Vector<User> v = new Vector<User>();

        if (res != null) {
            while (res.hasMoreElements()) {
                LDAPEntry entry = (LDAPEntry) res.nextElement();
                User user = buildUser(entry);

                v.addElement(user);
            }
        }

        // if v contains nothing, just throw exception
        if (v.size() == 0) {
            throw new EUsrGrpException("User not found");
        }

        return v.elements();
    }

    /**
     * builds a User instance. Sets only uid for user entry retrieved
     * from LDAP server. for listing efficiency only.
     *
     * @return the User entity.
     */
    protected User lbuildUser(LDAPEntry entry) throws EUsrGrpException {
        LDAPAttribute uid = entry.getAttribute("uid");
        if (uid == null) {
            throw new EUsrGrpException("No Attribute UID in LDAP Entry " + entry.getDN());
        }
        User id = createUser(uid.getStringValues().nextElement());
        LDAPAttribute cnAttr = entry.getAttribute("cn");

        if (cnAttr != null) {
            String cn = cnAttr.getStringValues().nextElement();

            if (cn != null) {
                id.setFullName(cn);
            }

        }

        LDAPAttribute certAttr =
                entry.getAttribute(LDAP_ATTR_USER_CERT);

        if (certAttr != null) {
            Vector<X509Certificate> certVector = new Vector<X509Certificate>();
            @SuppressWarnings("unchecked")
            Enumeration<byte[]> e = certAttr.getByteValues();

            try {
                for (; e != null && e.hasMoreElements();) {
                    X509Certificate cert = new X509CertImpl(
                             e.nextElement());

                    certVector.addElement(cert);
                }
            } catch (Exception ex) {
                throw new EUsrGrpException("Unable to get user certificate: " + ex.getMessage(), ex);
            }

            if (certVector != null && certVector.size() != 0) {
                // Make an array of certs
                X509Certificate[] certArray = new X509Certificate[certVector.size()];
                Enumeration<X509Certificate> en = certVector.elements();
                int i = 0;

                while (en.hasMoreElements()) {
                    certArray[i++] = en.nextElement();
                }

                id.setX509Certificates(certArray);
            }
        }

        return id;
    }

    /**
     * builds a User instance. Set all attributes retrieved from
     * LDAP server and set them on User.
     *
     * @return the User entity.
     */
    protected User buildUser(LDAPEntry entry) throws EUsrGrpException {
        LDAPAttribute uid = entry.getAttribute("uid");
        if (uid == null) {
            throw new EUsrGrpException("No Attribute UID in LDAP Entry " + entry.getDN());
        }
        User id = createUser(uid.getStringValues().nextElement());
        LDAPAttribute cnAttr = entry.getAttribute("cn");

        if (cnAttr != null) {
            String cn = cnAttr.getStringValues().nextElement();

            if (cn != null) {
                id.setFullName(cn);
            }
        }

        String userdn = entry.getDN();
        id.setUserDN(userdn);

        /*
         LDAPAttribute certdnAttr = entry.getAttribute(LDAP_ATTR_CERTDN);
         if (certdnAttr != null) {
         String cdn = certdnAttr.getStringValues().nextElement();
         if (cdn != null) {
         id.setCertDN(cdn);
         }
         }
         */
        LDAPAttribute mailAttr = entry.getAttribute("mail");

        if (mailAttr != null) {
            @SuppressWarnings("unchecked")
            Enumeration<String> en = mailAttr.getStringValues();

            if (en != null && en.hasMoreElements()) {
                String mail = en.nextElement();

                if (mail != null) {
                    id.setEmail(mail);
                }
            }
        }
        if (id.getEmail() == null) {
            id.setEmail(""); // safety net
        }

        LDAPAttribute pwdAttr = entry.getAttribute("userpassword");

        if (pwdAttr != null) {
            String pwd = pwdAttr.getStringValues().nextElement();

            if (pwd != null) {
                id.setPassword(pwd);
            }
        }
        LDAPAttribute phoneAttr = entry.getAttribute("telephonenumber");

        if (phoneAttr != null) {
            @SuppressWarnings("unchecked")
            Enumeration<String> en = phoneAttr.getStringValues();

            if (en != null && en.hasMoreElements()) {
                String phone = en.nextElement();

                if (phone != null) {
                    id.setPhone(phone);
                }
            }
        }
        if (id.getPhone() == null) {
            id.setPhone(""); // safety net
        }

        LDAPAttribute userTypeAttr = entry.getAttribute("usertype");

        if (userTypeAttr == null)
            id.setUserType("");
        else {
            @SuppressWarnings("unchecked")
            Enumeration<String> en = userTypeAttr.getStringValues();

            if (en != null && en.hasMoreElements()) {
                String userType = en.nextElement();

                if ((userType != null) && (!userType.equals("undefined")))
                    id.setUserType(userType);
                else
                    id.setUserType("");

            }
        }

        LDAPAttribute userStateAttr = entry.getAttribute("userstate");

        if (userStateAttr == null)
            id.setState("");
        else {
            @SuppressWarnings("unchecked")
            Enumeration<String> en = userStateAttr.getStringValues();

            if (en != null && en.hasMoreElements()) {
                String userState = en.nextElement();

                if (userState != null)
                    id.setState(userState);
                else
                    id.setState("");

            }
        }

        LDAPAttribute certAttr =
                entry.getAttribute(LDAP_ATTR_USER_CERT);

        if (certAttr != null) {
            Vector<X509Certificate> certVector = new Vector<X509Certificate>();
            @SuppressWarnings("unchecked")
            Enumeration<byte[]> e = certAttr.getByteValues();

            try {
                for (; e != null && e.hasMoreElements();) {
                    X509Certificate cert = new X509CertImpl(e.nextElement());
                    certVector.addElement(cert);
                }
            } catch (Exception ex) {
                throw new EUsrGrpException("Unable to get user certificate: " + ex.getMessage(), ex);
            }

            if (certVector != null && certVector.size() != 0) {
                // Make an array of certs
                X509Certificate[] certArray = new X509Certificate[certVector.size()];
                Enumeration<X509Certificate> en = certVector.elements();
                int i = 0;

                while (en.hasMoreElements()) {
                    certArray[i++] = en.nextElement();
                }

                id.setX509Certificates(certArray);
            }
        }

        LDAPAttribute profileAttr = entry.getAttribute(LDAP_ATTR_PROFILE_ID);
        if (profileAttr != null) {
            @SuppressWarnings("unchecked")
            Enumeration<String> profiles = profileAttr.getStringValues();
            id.setTpsProfiles(Collections.list(profiles));
        }

        return id;
    }

    /**
     * Adds identity. Certificates handled by a separate call to
     * addUserCert()
     */
    public void addUser(User identity) throws EUsrGrpException {
        User id = identity;

        if (id == null) {
            throw new EUsrGrpException("Unable to add user: Missing user");
        }

        if (id.getUserID() == null) {
            throw new EUsrGrpException("Unable to add user: Missing UID");
        }

        String dn = "uid=" + LDAPUtil.escapeRDNValue(id.getUserID()) + "," + getUserBaseDN();
        logger.info("UGSubsystem: adding " + dn);

        LDAPAttributeSet attrs = new LDAPAttributeSet();
        List<String> oclist = new ArrayList<String>();
        oclist.add("top");
        oclist.add("person");
        oclist.add("organizationalPerson");
        oclist.add("inetOrgPerson");
        oclist.add("cmsuser");

        if (id.getTpsProfiles() != null) {
            oclist.add("tpsProfileID");
        }

        logger.info("UGSubsystem: - " + OBJECTCLASS_ATTR + ": " + oclist);
        String[] oc = oclist.toArray(new String[oclist.size()]);
        attrs.add(new LDAPAttribute(OBJECTCLASS_ATTR, oc));

        logger.info("UGSubsystem: - uid: " + id.getUserID());
        attrs.add(new LDAPAttribute("uid", id.getUserID()));

        logger.info("UGSubsystem: - sn: " + id.getFullName());
        attrs.add(new LDAPAttribute("sn", id.getFullName()));

        logger.info("UGSubsystem: - cn: " + id.getFullName());
        attrs.add(new LDAPAttribute("cn", id.getFullName()));

        logger.info("UGSubsystem: - mail: " + id.getEmail());
        attrs.add(new LDAPAttribute("mail", id.getEmail()));

        // DS syntax checking requires a value for PrintableString syntax
        String phone = id.getPhone();
        if (phone != null && !phone.equals("")) {
            logger.info("UGSubsystem: - telephonenumber: " + phone);
            attrs.add(new LDAPAttribute("telephonenumber", phone));
        }

        logger.info("UGSubsystem: - userpassword: ********");
        attrs.add(new LDAPAttribute("userpassword", id.getPassword()));

        String userType = id.getUserType();
        if (userType != null) {
            // DS syntax checking requires a value for Directory String syntax
            // but usertype is a MUST attribute, so we need to add something here
            // if it is undefined.
            if (userType.equals("")) {
                userType = "undefined";
            }

            logger.info("UGSubsystem: - usertype: " + userType);
            attrs.add(new LDAPAttribute("usertype", userType));
        }

        // DS syntax checking requires a value for Directory String syntax
        String state = id.getState();
        if (state != null && !state.equals("")) {
            logger.info("UGSubsystem: - userstate: " + state);
            attrs.add(new LDAPAttribute("userstate", state));
        }

        // TODO add audit logging for profile
        List<String> profiles = id.getTpsProfiles();
        if (profiles != null && profiles.size() > 0) {
            LDAPAttribute attr = new LDAPAttribute(LDAP_ATTR_PROFILE_ID);
            for (String profile : profiles) {
                logger.info("UGSubsystem: - " + LDAP_ATTR_PROFILE_ID + ": " + profile);
                attr.addValue(profile);
            }
            attrs.add(attr);
        }

        LDAPEntry entry = new LDAPEntry(dn, attrs);
        // for audit log
        SessionContext sessionContext = SessionContext.getContext();
        String adminId = (String) sessionContext.get(SessionContext.USER_ID);

        logger.info(
                AuditFormat.ADDUSERFORMAT,
                adminId,
                id.getUserID()
        );

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            ldapconn.add(entry);

        } catch (LDAPException e) {
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            throw new EUsrGrpException("Unable to add user: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }

    /**
     * adds a user certificate to user
     */
    public void addUserCert(User identity) throws EUsrGrpException {
        User user = identity;

        if (user == null) {
            return;
        }

        X509Certificate cert[] = null;
        LDAPModificationSet addCert = new LDAPModificationSet();

        if ((cert = user.getX509Certificates()) != null) {
            LDAPAttribute attrCertStr = new LDAPAttribute(LDAP_ATTR_USER_CERT_STRING);
            LDAPAttribute attrCertBin = new LDAPAttribute(LDAP_ATTR_USER_CERT);

            try {
                attrCertBin.addValue(cert[0].getEncoded());
                attrCertStr.addValue(getCertificateString(cert[0]));
            } catch (CertificateEncodingException e) {
                throw new EUsrGrpException("Unable to add user certificate: " + e.getMessage(), e);
            }

            addCert.add(LDAPModification.ADD, attrCertStr);
            addCert.add(LDAPModification.ADD, attrCertBin);

            LDAPConnection ldapconn = null;

            try {
                ldapconn = getConn();
                ldapconn.modify("uid=" + LDAPUtil.escapeRDNValue(user.getUserID()) +
                        "," + getUserBaseDN(), addCert);
                // for audit log
                SessionContext sessionContext = SessionContext.getContext();
                String adminId = (String) sessionContext.get(SessionContext.USER_ID);

                logger.info(
                        AuditFormat.ADDUSERCERTFORMAT,
                        adminId,
                        user.getUserID(),
                        cert[0].getSubjectDN(),
                        cert[0].getSerialNumber().toString(16)
                );

            } catch (LDAPException e) {
                throw LDAPExceptionConverter.toPKIException(e);

            } catch (ELdapException e) {
                throw new EUsrGrpException("Unable to add user: " + e.getMessage(), e);

            } finally {
                if (ldapconn != null)
                    returnConn(ldapconn);
            }
        }

        return;
    }

    public void addCertSubjectDN(User identity) throws EUsrGrpException {
        User user = identity;

        if (user == null) {
            return;
        }

        X509Certificate cert[] = null;
        LDAPModificationSet addCert = new LDAPModificationSet();

        if ((cert = user.getX509Certificates()) != null) {
            LDAPAttribute attrCertDNStr = new LDAPAttribute(LDAP_ATTR_CERTDN);
            attrCertDNStr.addValue(cert[0].getSubjectDN().toString());
            addCert.add(LDAPModification.ADD, attrCertDNStr);

            LDAPConnection ldapconn = null;

            try {
                ldapconn = getConn();
                ldapconn.modify("uid=" + LDAPUtil.escapeRDNValue(user.getUserID()) +
                        "," + getUserBaseDN(), addCert);
                // for audit log
                SessionContext sessionContext = SessionContext.getContext();
                String adminId = (String) sessionContext.get(SessionContext.USER_ID);

                logger.info(
                        AuditFormat.ADDCERTSUBJECTDNFORMAT,
                        adminId,
                        user.getUserID(),
                        cert[0].getSubjectDN()
                );

            } catch (LDAPException e) {
                throw LDAPExceptionConverter.toPKIException(e);

            } catch (ELdapException e) {
                throw new EUsrGrpException("Unable to modify user: " + e.getMessage(), e);

            } finally {
                if (ldapconn != null)
                    returnConn(ldapconn);
            }
        }

        return;
    }

    public void removeCertSubjectDN(User identity) throws EUsrGrpException {
        User user = identity;

        if (user == null) {
            logger.warn("removeCertSubjectDN: null user passed in");
            return;
        }

        X509Certificate cert[] = null;
        LDAPModificationSet delAttr = new LDAPModificationSet();

        if ((cert = user.getX509Certificates()) != null) {
            LDAPAttribute attrCertDNStr = new LDAPAttribute(LDAP_ATTR_CERTDN);
            attrCertDNStr.addValue(cert[0].getSubjectDN().toString());
            delAttr.add(LDAPModification.DELETE, attrCertDNStr);

            LDAPConnection ldapconn = null;

            try {
                ldapconn = getConn();
                ldapconn.modify("uid=" + LDAPUtil.escapeRDNValue(user.getUserID()) +
                        "," + getUserBaseDN(), delAttr);
                // for audit log
                SessionContext sessionContext = SessionContext.getContext();
                String adminId = (String) sessionContext.get(SessionContext.USER_ID);

                logger.info(
                        AuditFormat.REMOVECERTSUBJECTDNFORMAT,
                        adminId,
                        user.getUserID(),
                        cert[0].getSubjectDN()
                );

            } catch (LDAPException e) {
                throw LDAPExceptionConverter.toPKIException(e);

            } catch (ELdapException e) {
                throw new EUsrGrpException("Unable to modify user: " + e.getMessage(), e);

            } finally {
                if (ldapconn != null)
                    returnConn(ldapconn);
            }
        }
        return;
    }

    /**
     * Removes a user certificate for a user entry
     * given a user certificate DN (actually, a combination of version,
     * serialNumber, issuerDN, and SubjectDN), and it gets removed
     */
    public void removeUserCert(User identity) throws EUsrGrpException {
        User user = identity;
        User ldapUser = null;

        if (user == null) {
            return;
        }

        // retrieve all certs of the user, then match the cert String for
        // removal
        ldapUser = getUser(user.getUserID());

        if (ldapUser == null) {
            throw new ResourceNotFoundException("User not found: " + user.getUserID());
        }

        X509Certificate[] certs = ldapUser.getX509Certificates();

        if (certs == null) {
            throw new ResourceNotFoundException("User certificate not found");
        }

        String delCertdn = user.getCertDN();

        if (delCertdn == null) {
            throw new ResourceNotFoundException("User certificate not found");
        }

        int certCount = 0;

        for (int i = 0; i < certs.length; i++) {
            String certStr;

            if (delCertdn.startsWith("-1;")) {
                certStr = getCertificateStringWithoutVersion(certs[i]);
            } else {
                certStr = getCertificateString(certs[i]);
            }

            if (!delCertdn.equalsIgnoreCase(certStr)) continue;

            LDAPConnection ldapconn = null;

            try {
                ldapconn = getConn();

                String dn = "uid=" + LDAPUtil.escapeRDNValue(user.getUserID()) + "," + getUserBaseDN();

                try {
                    // remove seeAlso attribute
                    LDAPModificationSet attrs = new LDAPModificationSet();
                    LDAPAttribute certDNAttrS = new LDAPAttribute(LDAP_ATTR_CERTDN);
                    certDNAttrS.addValue(certs[i].getSubjectDN().toString());
                    attrs.add(LDAPModification.DELETE, certDNAttrS);
                    ldapconn.modify(dn, attrs);

                } catch (LDAPException e) {
                    if (e.getLDAPResultCode() == 16) { // ignore missing seeAlso attribute
                        logger.warn("removeUserCert: No attribute "+LDAP_ATTR_CERTDN+" in entry "+dn);
                    } else {
                        throw LDAPExceptionConverter.toPKIException(e);
                    }
                }

                // remove userCertificate and description attributes
                LDAPModificationSet attrs = new LDAPModificationSet();

                LDAPAttribute certAttr = new LDAPAttribute(LDAP_ATTR_USER_CERT);
                certAttr.addValue(certs[i].getEncoded());
                attrs.add(LDAPModification.DELETE, certAttr);

                LDAPAttribute certAttrS = new LDAPAttribute(LDAP_ATTR_USER_CERT_STRING);
                certAttrS.addValue(getCertificateString(certs[i]));
                attrs.add(LDAPModification.DELETE, certAttrS);

                ldapconn.modify(dn, attrs);

                certCount++;

                // for audit log
                SessionContext sessionContext = SessionContext.getContext();
                String adminId = (String) sessionContext.get(SessionContext.USER_ID);

                logger.info(
                        AuditFormat.REMOVEUSERCERTFORMAT,
                        adminId,
                        user.getUserID(),
                        certs[0].getSubjectDN(),
                        certs[i].getSerialNumber().toString(16)
                );

            } catch (CertificateEncodingException e) {
                throw new EUsrGrpException(e.getMessage(), e);

            } catch (LDAPException e) {
                throw LDAPExceptionConverter.toPKIException(e);

            } catch (ELdapException e) {
                throw new EUsrGrpException("Unable to remove user certificate: " + e.getMessage(), e);

            } finally {
                if (ldapconn != null)
                    returnConn(ldapconn);
            }
        }

        if (certCount == 0) {
            throw new EUsrGrpException("User certificate not found");
        }
    }

    public void addUserToGroup(Group grp, String userid)
            throws EUsrGrpException {

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            String groupDN = "cn=" + LDAPUtil.escapeRDNValue(grp.getGroupID()) +
                    "," + getGroupBaseDN();
            LDAPAttribute memberAttr = new LDAPAttribute(
                    "uniquemember", "uid=" + LDAPUtil.escapeRDNValue(userid) + "," + getUserBaseDN());
            LDAPModification singleChange = new LDAPModification(
                    LDAPModification.ADD, memberAttr);

            ldapconn.modify(groupDN, singleChange);

        } catch (LDAPException e) {
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            throw new EUsrGrpException("Unable to add user to group: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }

    public void removeUserFromGroup(Group grp, String userid)
            throws EUsrGrpException {

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            String groupDN = "cn=" + LDAPUtil.escapeRDNValue(grp.getGroupID()) +
                    "," + getGroupBaseDN();
            LDAPAttribute memberAttr = new LDAPAttribute(
                    "uniquemember", "uid=" + LDAPUtil.escapeRDNValue(userid) + "," + getUserBaseDN());
            LDAPModification singleChange = new LDAPModification(
                    LDAPModification.DELETE, memberAttr);

            ldapconn.modify(groupDN, singleChange);

        } catch (LDAPException e) {
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            throw new EUsrGrpException("Unable to remove user from group: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }

    /**
     * Removes identity.
     */
    public void removeUser(String userid) throws EUsrGrpException {
        if (userid == null) {
            return;
        }

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            ldapconn.delete("uid=" + LDAPUtil.escapeRDNValue(userid) + "," + getUserBaseDN());
            // for audit log
            SessionContext sessionContext = SessionContext.getContext();
            String adminId = (String) sessionContext.get(SessionContext.USER_ID);

            logger.info(
                    AuditFormat.REMOVEUSERFORMAT,
                    adminId,
                    userid
            );

        } catch (LDAPException e) {
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            logger.error("Unable to remove user: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }


    /**
     * modifies user attributes. Certs are handled separately
     */
    public void modifyUser(User identity) throws EUsrGrpException {
        User user = identity;
        String st = null;

        /**
         * X509Certificate certs[] = null;
         **/
        LDAPModificationSet attrs = new LDAPModificationSet();

        if (user == null) {
            return;
        }

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            if ((st = user.getFullName()) != null) {
                attrs.add(LDAPModification.REPLACE,
                        new LDAPAttribute("sn", st));
                attrs.add(LDAPModification.REPLACE,
                        new LDAPAttribute("cn", st));
            }
            if ((st = user.getEmail()) != null) {
                LDAPAttribute ld = new LDAPAttribute("mail", st);

                attrs.add(LDAPModification.REPLACE, ld);
            }
            if ((st = user.getPassword()) != null && (!st.equals(""))) {
                attrs.add(LDAPModification.REPLACE,
                        new LDAPAttribute("userpassword", st));
            }
            if ((st = user.getPhone()) != null) {
                if (!st.equals("")) {
                    attrs.add(LDAPModification.REPLACE,
                            new LDAPAttribute("telephonenumber", st));
                } else {
                    try {
                        LDAPModification singleChange = new LDAPModification(
                                LDAPModification.DELETE, new LDAPAttribute("telephonenumber"));
                        ldapconn.modify("uid=" + LDAPUtil.escapeRDNValue(user.getUserID()) +
                                "," + getUserBaseDN(), singleChange);
                    } catch (LDAPException e) {
                        if (e.getLDAPResultCode() != LDAPException.NO_SUCH_ATTRIBUTE) {
                            logger.error("modifyUser: Error in deleting telephonenumber: " + e.getMessage(), e);
                            throw e;
                        }
                    }
                }
            }

            if ((st = user.getState()) != null) {
                if (!st.equals("")) {
                    attrs.add(LDAPModification.REPLACE,
                            new LDAPAttribute("userstate", st));
                } else {
                    try {
                        LDAPModification singleChange = new LDAPModification(
                                LDAPModification.DELETE, new LDAPAttribute("userstate"));
                        ldapconn.modify("uid=" + LDAPUtil.escapeRDNValue(user.getUserID()) +
                                "," + getUserBaseDN(), singleChange);
                    } catch (LDAPException e) {
                        if (e.getLDAPResultCode() != LDAPException.NO_SUCH_ATTRIBUTE) {
                            logger.error("modifyUser: Error in deleting userstate: " + e.getMessage(), e);
                            throw e;
                        }
                    }
                }
            }

            List<String> profiles = user.getTpsProfiles();
            if (profiles != null) {
                // TODO add audit logging for profile

                // replace the objectclass in case tpsProfile is not present
                String oc[] = { "top", "person", "organizationalPerson",
                        "inetOrgPerson", "cmsuser", "tpsProfileID" };
                attrs.add(LDAPModification.REPLACE,
                        new LDAPAttribute(OBJECTCLASS_ATTR, oc));

                LDAPAttribute attr = new LDAPAttribute(LDAP_ATTR_PROFILE_ID);
                for (String profile : profiles) {
                    attr.addValue(profile);
                }
                attrs.add(LDAPModification.REPLACE, attr);
            }

            /**
             * if ((certs = user.getCertificates()) != null) {
             * LDAPAttribute attrCertStr = new
             * LDAPAttribute("description");
             * LDAPAttribute attrCertBin = new
             * LDAPAttribute(LDAP_ATTR_USER_CERT);
             * for (int i = 0 ; i < certs.length; i++) {
             * attrCertBin.addValue(certs[i].getEncoded());
             * attrCertStr.addValue(getCertificateString(certs[i]));
             * }
             * attrs.add(attrCertStr);
             *
             * if (user.getCertOp() == OpDef.ADD) {
             * attrs.add(LDAPModification.ADD, attrCertBin);
             * } else if (user.getCertOp() == OpDef.DELETE) {
             * attrs.add(LDAPModification.DELETE, attrCertBin);
             * } else {
             * throw new EUsrGrpException(UsrGrpResources.USR_MOD_ILL_CERT_OP);
             * }
             * }
             **/
            ldapconn.modify("uid=" + LDAPUtil.escapeRDNValue(user.getUserID()) +
                    "," + getUserBaseDN(), attrs);
            // for audit log
            SessionContext sessionContext = SessionContext.getContext();
            String adminId = (String) sessionContext.get(SessionContext.USER_ID);

            logger.info(
                    AuditFormat.MODIFYUSERFORMAT,
                    adminId,
                    user.getUserID()
            );

        } catch (LDAPException e) {
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            throw new EUsrGrpException("Unable to modify user: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }

    protected Enumeration<Group> buildGroups(LDAPSearchResults res) throws EUsrGrpException {
        Vector<Group> v = new Vector<Group>();

        while (res.hasMoreElements()) {
            LDAPEntry entry = (LDAPEntry) res.nextElement();

            v.addElement(buildGroup(entry));
        }
        return v.elements();
    }

    /**
     * Finds groups.
     * @throws EUsrGrpException
     */
    public Enumeration<Group> findGroups(String filter) throws EUsrGrpException {

        if (filter == null) {
            return null;
        }

        String baseDN = getGroupBaseDN();
        logger.debug("UGSubsystem: Retrieving groups from " + baseDN);

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            LDAPSearchResults res = ldapconn.search(
                    baseDN,
                    LDAPv2.SCOPE_SUB,
                    "(&(objectclass=groupofuniquenames)(cn=" + filter + "))",
                    null,
                    false);

            return buildGroups(res);

        } catch (LDAPException e) {
            logger.error("Unable to find groups: " + e, e);
            return null;

        } catch (ELdapException e) {
            logger.error("Unable to find groups: " + e, e);
            return null;

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }

    public Group findGroup(String filter) throws EUsrGrpException {
        Enumeration<Group> groups = findGroups(filter);

        if (groups == null || !groups.hasMoreElements())
            return null;
        return groups.nextElement();
    }

    /**
     * List groups. more efficient than find Groups. only retrieves
     * group names and description.
     */
    public Enumeration<Group> listGroups(String filter) throws EUsrGrpException {

        String ldapFilter;

        if (filter == null) {
            ldapFilter = "(objectclass=groupofuniquenames)";

        } else {
            filter = LDAPUtil.escapeFilter(filter);
            ldapFilter = "(&(objectclass=groupofuniquenames)(cn=*" + filter + "*))";
        }

        String attrs[] = new String[2];
        attrs[0] = "cn";
        attrs[1] = "description";

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            LDAPSearchResults res = ldapconn.search(
                    getGroupBaseDN(),
                    LDAPv2.SCOPE_ONE,
                    ldapFilter,
                    attrs,
                    false);

            // doesn't throw exception if result is empty
            return buildGroups(res);

        } catch (LDAPException e) {
            logger.warn("Unable to list groups: " + e.getMessage(), e);

        } catch (ELdapException e) {
            logger.warn("Unable to list groups: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }

        return null;
    }

    public Enumeration<Group> findGroupsByUser(String userDn, String filter) throws EUsrGrpException {

        if (userDn == null) {
            return null;
        }

        // search groups where the user is a member
        String ldapFilter = "(&(objectclass=groupofuniquenames)(uniqueMember=" + LDAPUtil.escapeFilter(userDn) + ")";

        if (!StringUtils.isEmpty(filter)) {
            // combine search filter if specified
            filter = LDAPUtil.escapeFilter(filter);
            ldapFilter += "(cn=*" + filter + "*)";
        }

        ldapFilter += ")";

        LDAPConnection ldapconn = null;

        try {
            String attrs[] = new String[2];
            attrs[0] = "cn";
            attrs[1] = "description";

            ldapconn = getConn();

            LDAPSearchResults res = ldapconn.search(
                    getGroupBaseDN(),
                    LDAPv2.SCOPE_ONE,
                    ldapFilter,
                    attrs,
                    false);

            return buildGroups(res);

        } catch (LDAPException e) {
            logger.warn("Unable to find groups by user: " + e.getMessage(), e);

        } catch (ELdapException e) {
            logger.warn("Unable to find groups by user: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }

        return null;
    }

    /**
     * builds an instance of a Group entry
     * @throws EUsrGrpException
     */
    protected Group buildGroup(LDAPEntry entry) throws EUsrGrpException {
        LDAPAttribute cn = entry.getAttribute("cn");
        if (cn == null) {
            throw new EUsrGrpException("Cannot build group. No Attribute cn in LDAP Entry " + entry.getDN());
        }
        String groupName = cn.getStringValues().nextElement();
        Group grp = createGroup(groupName);

        LDAPAttribute grpDesc = entry.getAttribute("description");

        if (grpDesc != null) {
            @SuppressWarnings("unchecked")
            Enumeration<String> en = grpDesc.getStringValues();

            if (en != null && en.hasMoreElements()) {
                String desc = en.nextElement();

                if (desc != null) {
                    try {
                        grp.set("description", desc);
                    } catch (EBaseException ex) {
                        logger.warn("Unable to store group description: " + ex.getMessage(), ex);
                    }
                }
            }
        }
        if (grp.getDescription() == null) {
            try {
                grp.set("description", ""); // safety net
            } catch (EBaseException ex) {
                logger.warn("Unable to store group description: " + ex.getMessage(), ex);
            }
        }

        // parser member (should use late-materialization)
        LDAPAttribute attr = entry.getAttribute("uniquemember");

        if (attr == null) {
            return grp;
        }

        @SuppressWarnings("unchecked")
        Enumeration<String> e = attr.getStringValues();

        while (e.hasMoreElements()) {
            String v = e.nextElement();

            //		grp.addMemberName(v);
            // DOES NOT SUPPORT NESTED GROUPS...

            /* BAD_GROUP_MEMBER message goes to system log
             * We are testing unique member attribute for
             * 1. presence of uid string
             * 2. presence and sequence of equal sign and comma
             * 3. absence of equal sign between previously found equal sign and comma
             * 4. absence of non white space characters between uid string and equal sign
             */
            int i = -1;
            int j = -1;
            if (v == null || v.length() < 3 || (!(v.substring(0, 3)).equalsIgnoreCase("uid")) ||
                    ((i = v.indexOf('=')) < 0) || ((j = v.indexOf(',')) < 0) || i > j ||
                    (v.substring(i + 1, j)).indexOf('=') > -1 || ((v.substring(3, i)).trim()).length() > 0) {

                logger.warn("Invalid group member: " + v);

            } else {
                grp.addMemberName(v.substring(v.indexOf('=') + 1, v.indexOf(',')));
            }
        }

        return grp;
    }

    /**
     * Retrieves a group from LDAP
     * NOTE - this takes just the group name.
     */
    public Group getGroupFromName(String name) {
        return getGroup("cn=" + LDAPUtil.escapeRDNValue(name) + "," + getGroupBaseDN());
    }

    /**
     * Retrieves a group from LDAP
     * NOTE - LH This takes a full LDAP DN.
     */
    public Group getGroup(String groupDN) {
        if (groupDN == null) {
            return null;
        }

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            // read the group object
            LDAPSearchResults res = ldapconn.search(groupDN,
                    LDAPConnection.SCOPE_BASE, "(objectclass=*)", null, false);
            Enumeration<Group> e = buildGroups(res);

            if (e == null || e.hasMoreElements() == false)
                return null;
            return e.nextElement();

        } catch (Exception e) {
            logger.warn("Unable to get group: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
        return null;
    }

    /**
     * Checks if the given group exists
     */
    public boolean isGroupPresent(String name) {
        if (name == null) {
            return false;
        }

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            LDAPEntry entry = ldapconn.read(name);
            LDAPAttribute attr = entry.getAttribute(OBJECTCLASS_ATTR);

            if (attr == null) {
                return false;
            }
            @SuppressWarnings("unchecked")
            Enumeration<String> en = attr.getStringValues();

            for (; en.hasMoreElements();) {
                String v = en.nextElement();

                if (v.equalsIgnoreCase(GROUP_ATTR_VALUE)) {
                    return true;
                }
            }
        } catch (Exception e) {
            logger.warn("Unable to get group: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
        return false;
    }

    public boolean isMemberOf(String userid, String groupname) {
        try {
            User user = getUser(userid);
            if (user != null) {
                return isMemberOfLdapGroup(user.getUserDN(), groupname);
            }
        } catch (Exception e) {
            /* do nothing */
        }
        return false;
    }

    /**
     * Checks if the given user is a member of the given group
     * (now runs an ldap search to find the user, instead of
     * fetching the entire group entry)
     */
    public boolean isMemberOf(User id, String name) {
        if (id == null) {
            logger.warn("UGSubsystem: isMemberOf(): id is null");
            return false;
        }

        if (name == null) {
            logger.warn("UGSubsystem: isMemberOf(): name is null");
            return false;
        }

        logger.trace("UGSubsystem.isMemberOf() using new lookup code");
        return isMemberOfLdapGroup(id.getUserDN(), name);
    }

    /**
     * checks if the given user DN is in the specified group
     * by running an ldap search for the user in the group
     */
    protected boolean isMemberOfLdapGroup(String userid, String groupname) {
        String basedn = "cn=" + LDAPUtil.escapeRDNValue(groupname) + ",ou=groups," + mBaseDN;
        LDAPConnection ldapconn = null;
        boolean founduser = false;
        try {
            // the group could potentially have many thousands
            // of members, (many values of the uniquemember
            // attribute). So, we don't want to fetch this
            // list each time. We'll just fetch the CN.
            String attrs[] = new String[1];
            attrs[0] = "cn";

            ldapconn = getConn();

            String filter = "(uniquemember=" + LDAPUtil.escapeFilter(userid) + ")";
            logger.trace("authorization search base: " + basedn);
            logger.trace("authorization search filter: " + filter);
            LDAPSearchResults res =
                    ldapconn.search(basedn, LDAPv2.SCOPE_BASE,
                            filter,
                            attrs, false);
            // If the result had at least one entry, we know
            // that the filter matched, and so the user correctly
            // authenticated.
            if (res.hasMoreElements()) {
                res.nextElement(); // consume the entry
                founduser = true;
            }
            logger.trace("authorization result: " + founduser);
        } catch (LDAPException e) {
            String errMsg =
                    "isMemberOfLdapGroup: could not find group " + groupname + ". Error " + e;
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                errMsg = "isMemberOfLdapGroup: " + "Internal DB is unavailable";
            }
            logger.warn("UGSubsystem: authorization exception: " + errMsg);

        } catch (ELdapException e) {
            String errMsg =
                    "isMemberOfLdapGroup: Could not get connection to internaldb. Error " + e;
            logger.warn("UGSubsystem: authorization exception: " + errMsg);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
        return founduser;
    }

    /**
     * Adds a group of identities.
     */
    public void addGroup(Group group) throws EUsrGrpException {
        Group grp = group;

        if (grp == null) {
            return;
        }

        LDAPConnection ldapconn = null;

        try {
            String dn = "cn=" + LDAPUtil.escapeRDNValue(grp.getGroupID()) + "," + getGroupBaseDN();
            logger.info("UGSubsystem: adding " + dn);

            LDAPAttributeSet attrs = new LDAPAttributeSet();

            String[] oc = { "top", "groupOfUniqueNames" };
            logger.info("UGSubsystem: - objectclass: " + Arrays.asList(oc));
            attrs.add(new LDAPAttribute("objectclass", oc));

            logger.info("UGSubsystem: - cn: " + group.getGroupID());
            attrs.add(new LDAPAttribute("cn", group.getGroupID()));

            String description = group.getDescription();
            if (description != null) {
                logger.info("UGSubsystem: - description: " + description);
                attrs.add(new LDAPAttribute("description", description));
            }

            Enumeration<String> e = grp.getMemberNames();

            if (e.hasMoreElements()) {
                LDAPAttribute attrMembers = new LDAPAttribute("uniquemember");

                while (e.hasMoreElements()) {
                    String name = e.nextElement();

                    String memberDN = "uid=" + LDAPUtil.escapeRDNValue(name) + "," + getUserBaseDN();
                    logger.info("UGSubsystem: - uniqueMember: " + memberDN);
                    attrMembers.addValue(memberDN);
                }

                attrs.add(attrMembers);
            }

            LDAPEntry entry = new LDAPEntry(dn, attrs);

            ldapconn = getConn();
            ldapconn.add(entry);

        } catch (LDAPException e) {
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            throw new EUsrGrpException("Unable to add group: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }

    /**
     * Removes a group. Can't remove SUPER_CERT_ADMINS
     */
    public void removeGroup(String name) throws EUsrGrpException {
        if (name == null) {
            return;
        } else if (name.equalsIgnoreCase(SUPER_CERT_ADMINS)) {
            throw new EUsrGrpException("Unable to remove " + SUPER_CERT_ADMINS + " group");
        }

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            ldapconn.delete("cn=" + LDAPUtil.escapeRDNValue(name) + "," + getGroupBaseDN());

        } catch (LDAPException e) {
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            throw new EUsrGrpException("Unable to remove group: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }

    /**
     * Modifies an existing group in the database.
     *
     * @param group   an existing group that has been modified in memory
     */
    public void modifyGroup(Group group) throws EUsrGrpException {
        Group grp = group;

        if (grp == null) {
            return;
        }

        LDAPConnection ldapconn = null;

        try {
            String dn = "cn=" + LDAPUtil.escapeRDNValue(grp.getGroupID()) + "," + getGroupBaseDN();
            logger.debug("dn: " + dn);

            LDAPModificationSet mod = new LDAPModificationSet();

            // update description
            String description = grp.getDescription();
            mod.add(LDAPModification.REPLACE, new LDAPAttribute("description", description));
            logger.debug("description: " + description);

            Enumeration<String> e = grp.getMemberNames();

            // admin group cannot be empty
            if (grp.getName().equalsIgnoreCase(SUPER_CERT_ADMINS) && !e.hasMoreElements()) {
                throw new EUsrGrpException("Unable to remove the last member of " + SUPER_CERT_ADMINS + " group");
            }

            // update members
            LDAPAttribute attrMembers = new LDAPAttribute("uniquemember");
            while (e.hasMoreElements()) {
                String name = e.nextElement();

                String memberDN = "uid=" + LDAPUtil.escapeRDNValue(name) + "," + getUserBaseDN();
                logger.debug("uniqueMember: " + memberDN);

                // DOES NOT SUPPORT NESTED GROUPS...
                attrMembers.addValue(memberDN);
            }
            mod.add(LDAPModification.REPLACE, attrMembers);

            ldapconn = getConn();
            ldapconn.modify(dn, mod);

        } catch (LDAPException e) {
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            throw new EUsrGrpException("Unable to modify group: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }

    /**
     * Evalutes the given context with the attribute
     * critieria.
     */
    public boolean evaluate(String type, User id,
            String op, String value) {
        if (op.equals("=")) {
            if (type.equalsIgnoreCase("user")) {
                if (isMatched(value, id.getUserID()))
                    return true;
            }
            if (type.equalsIgnoreCase("group")) {
                return isMemberOf(id, value);
            }
        }
        return false;
    }

    /**
     * Converts an uid attribute to a DN.
     */
    protected String convertUIDtoDN(String uid) throws
            LDAPException {
        String u = uid;

        if (u == null) {
            return null;
        }

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            LDAPSearchResults res = ldapconn.search(getUserBaseDN(),
                    LDAPv2.SCOPE_SUB, "(uid=" + LDAPUtil.escapeFilter(u) + ")", null, false);

            if (res.hasMoreElements()) {
                LDAPEntry entry = (LDAPEntry) res.nextElement();

                return entry.getDN();
            }

        } catch (ELdapException e) {
            logger.warn("Unable to convert UID to DN: " + e.getMessage(), e);

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
        return null;
    }

    /**
     * Checks if the given DNs are the same after
     * normalization.
     */
    protected boolean isMatched(String dn1, String dn2) {
        String rdn1[] = LDAPDN.explodeDN(dn1, false);
        String rdn2[] = LDAPDN.explodeDN(dn2, false);
        if (rdn1 == null && rdn2 == null) {
            return true;
        }
        if (rdn1 == null || rdn2 == null) {
            return false;
        }

        if (rdn1.length == rdn2.length) {
            for (int j = 0; j < rdn1.length; j++) {
                if (!rdn1[j].equalsIgnoreCase(rdn2[j])) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    /**
     * Converts certificate into string format.
     * should eventually go into the locator itself
     */
    protected String getCertificateStringWithoutVersion(X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        // note that it did not represent a certificate fully
        return "-1;" + cert.getSerialNumber().toString() +
                ";" + cert.getIssuerDN() + ";" + cert.getSubjectDN();
    }

    public String getCertificateString(X509Certificate cert) {
        if (cert == null) {
            return null;
        }

        // note that it did not represent a certificate fully
        return cert.getVersion() + ";" + cert.getSerialNumber().toString() +
                ";" + cert.getIssuerDN() + ";" + cert.getSubjectDN();
    }

    /**
     * Retrieves user base dn.
     */
    private String getUserBaseDN() {
        return "ou=People," + mBaseDN;
    }

    public String getUserDN(String userID) {
        return "uid=" + LDAPUtil.escapeRDNValue(userID) + "," + getUserBaseDN();
    }

    /**
     * Retrieves group base dn.
     */
    private String getGroupBaseDN() {
        return "ou=Groups," + mBaseDN;
    }

    protected LDAPConnection getConn() throws ELdapException {
        if (mLdapConnFactory != null) {
            LDAPConnection conn = mLdapConnFactory.getConn();
            if (conn == null) {
                throw new ELdapException("No Ldap Connection Available");
            } else {
                return conn;
            }
        }

        throw new ELdapException("Ldap Connection Factory is Unavailable");
    }

    protected void returnConn(LDAPConnection conn) {
        if (mLdapConnFactory != null)
            mLdapConnFactory.returnConn(conn);
    }
}
