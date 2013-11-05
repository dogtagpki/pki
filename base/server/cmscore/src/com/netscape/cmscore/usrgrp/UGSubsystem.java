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
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;

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
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.LDAPExceptionConverter;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.certsrv.usrgrp.ICertUserLocator;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.certsrv.usrgrp.IUsrGrp;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * This class defines low-level LDAP usr/grp management
 * usr/grp information is located remotely on another
 * LDAP server.
 *
 * @author thomask
 * @author cfu
 * @version $Revision$, $Date$
 */
public final class UGSubsystem implements IUGSubsystem {

    private static final long serialVersionUID = 8080165044652629774L;
    public static final String ID = "usrgrp";
    private String mId = ID;

    protected static final String OBJECTCLASS_ATTR = "objectclass";
    protected static final String MEMBER_ATTR = "uniquemember";
    protected static final String GROUP_ATTR_VALUE = "groupofuniquenames";

    protected static final String LDAP_ATTR_USER_CERT_STRING = "description";
    protected static final String LDAP_ATTR_CERTDN = "seeAlso";
    protected static final String LDAP_ATTR_USER_CERT = "userCertificate";
    protected static final String LDAP_ATTR_PROFILE_ID = "profileID";

    protected static final String PROP_BASEDN = "basedn";

    protected IConfigStore mConfig = null;
    protected transient LdapBoundConnFactory mLdapConnFactory = null;
    protected String mBaseDN = null;
    protected static UGSubsystem mUG = null;

    private transient ILogger mLogger = null;

    // singleton enforcement

    private static UGSubsystem mInstance = new UGSubsystem();

    public static UGSubsystem getInstance() {
        return mInstance;
    }

    // end singleton enforcement.

    /**
     * Constructs LDAP based usr/grp management
     */
    private UGSubsystem() {
    }

    /**
     * Retrieves identifier of this scope.
     */
    public String getId() {
        return mId;
    }

    /**
     * Sets identifier of this manager
     */
    public void setId(String id) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));
    }

    /**
     * Connects to LDAP server.
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mLogger = CMS.getLogger();
        mConfig = config;

        // initialize LDAP connection factory
        try {
            IConfigStore ldapConfig = mConfig.getSubStore("ldap");

            mBaseDN = ldapConfig.getString(PROP_BASEDN, null);

            mLdapConnFactory = new LdapBoundConnFactory();
            mLdapConnFactory.init(ldapConfig);
        } catch (EBaseException e) {
            if (CMS.isPreOpMode())
                return;
            throw e;
        }
    }

    /**
     * Starts up this service.
     */
    public void startup() throws EBaseException {
        // register admin servlet

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
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_LDAP_SHUT", e.toString()));
        }
    }

    public IUser createUser(String id) {
        return new User(this, id);
    }

    public IGroup createGroup(String id) {
        return new Group(this, id);
    }

    /**
     * Retrieves configuration store.
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Retrieves the description of this scope.
     */
    public String getDescription() {
        return "User/Group Manager";
    }

    /**
     * Retrieves a user from LDAP
     */
    public IUser getUser(String userid) throws EUsrGrpException {
        if (userid == null) {
            return null;
        }

        try {
            if (userid.indexOf('=') == -1) {
                Enumeration<IUser> e = findUsers(userid);

                if (e != null && e.hasMoreElements()) {
                    IUser u = e.nextElement();

                    return u;
                } else {
                    throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_USER_NOT_FOUND"));
                }
            } else {
                LDAPConnection ldapconn = null;

                try {
                    ldapconn = getConn();
                    // read DN
                    LDAPSearchResults res =
                            ldapconn.search(userid,
                                    LDAPv2.SCOPE_SUB, "(objectclass=*)", null, false);
                    Enumeration<IUser> e = buildUsers(res);

                    if (e.hasMoreElements()) {
                        return e.nextElement();
                    }
                } finally {
                    if (ldapconn != null)
                        returnConn(ldapconn);
                }
            }
        } catch (Exception e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_GET_USER", e.toString()));
            // throws...
        }
        return null;
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
            Enumeration<IUser> e = buildUsers(res);

            return (User) e.nextElement();
        } catch (LDAPException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_FIND_USER", e.toString()));
        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_INTERNAL_DB", e.toString()));
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
    public IUser findUsersByCert(String filter) throws EUsrGrpException {
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

            Enumeration<IUser> e = buildUsers(res);

            return e.nextElement();

        } catch (LDAPException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_FIND_USER_BY_CERT", e.toString()));

        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_FIND_USER_BY_CERT", e.toString()));

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }

        return null;
    }

    /**
     * Searchs for identities that matches the filter.
     */
    public Enumeration<IUser> findUsers(String filter) throws EUsrGrpException {
        if (filter == null) {
            return null;
        }

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            LDAPSearchResults res = ldapconn.search(getUserBaseDN(),
                    LDAPv2.SCOPE_SUB, "(uid=" + filter + ")",
                    null, false);

            Enumeration<IUser> e = buildUsers(res);

            return e;
        } catch (LDAPException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_FIND_USERS", e.toString()));
        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_FIND_USERS", e.toString()));
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
    public Enumeration<IUser> listUsers(String filter) throws EUsrGrpException {
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
            Enumeration<IUser> e = lbuildUsers(res);

            return e;
        } catch (LDAPException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_LIST_USERS", e.toString()));
        } catch (Exception e) {
            throw new EUsrGrpException(CMS.getUserMessage("CMS_INTERNAL_ERROR"));
        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }

        return null;
    }

    protected Enumeration<IUser> lbuildUsers(LDAPSearchResults res) throws
            EUsrGrpException {
        Vector<IUser> v = new Vector<IUser>();

        while (res.hasMoreElements()) {
            LDAPEntry entry = (LDAPEntry) res.nextElement();
            IUser user = lbuildUser(entry);

            v.addElement(user);
        }
        return v.elements();
    }

    protected Enumeration<IUser> buildUsers(LDAPSearchResults res) throws
            EUsrGrpException {
        Vector<IUser> v = new Vector<IUser>();

        if (res != null) {
            while (res.hasMoreElements()) {
                LDAPEntry entry = (LDAPEntry) res.nextElement();
                IUser user = buildUser(entry);

                v.addElement(user);
            }
        }

        // if v contains nothing, just throw exception
        if (v.size() == 0) {
            throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_USER_NOT_FOUND"));
        }

        return v.elements();
    }

    /**
     * builds a User instance. Sets only uid for user entry retrieved
     * from LDAP server. for listing efficiency only.
     *
     * @return the User entity.
     */
    protected IUser lbuildUser(LDAPEntry entry) throws EUsrGrpException {
        LDAPAttribute uid = entry.getAttribute("uid");
        if (uid == null) {
            throw new EUsrGrpException("No Attribute UID in LDAP Entry " + entry.getDN());
        }
        IUser id = createUser(this, (String) uid.getStringValues().nextElement());
        LDAPAttribute cnAttr = entry.getAttribute("cn");

        if (cnAttr != null) {
            String cn = (String) cnAttr.getStringValues().nextElement();

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
                throw new EUsrGrpException(CMS.getUserMessage("CMS_INTERNAL_ERROR"));
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
    protected IUser buildUser(LDAPEntry entry) throws EUsrGrpException {
        LDAPAttribute uid = entry.getAttribute("uid");
        if (uid == null) {
            throw new EUsrGrpException("No Attribute UID in LDAP Entry " + entry.getDN());
        }
        IUser id = createUser(this, (String) uid.getStringValues().nextElement());
        LDAPAttribute cnAttr = entry.getAttribute("cn");

        if (cnAttr != null) {
            String cn = (String) cnAttr.getStringValues().nextElement();

            if (cn != null) {
                id.setFullName(cn);
            }
        }

        String userdn = entry.getDN();

        if (userdn != null) {
            id.setUserDN(userdn);
        } else { // the impossible
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_BUILD_USER", userdn));

            throw new EUsrGrpException(CMS.getUserMessage("CMS_INTERNAL_ERROR"));
        }

        /*
         LDAPAttribute certdnAttr = entry.getAttribute(LDAP_ATTR_CERTDN);
         if (certdnAttr != null) {
         String cdn = (String)certdnAttr.getStringValues().nextElement();
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
            String pwd = (String) pwdAttr.getStringValues().nextElement();

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
                throw new EUsrGrpException(CMS.getUserMessage("CMS_INTERNAL_ERROR"));
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

    protected IUser createUser(IUsrGrp base, String id) {
        return new User(base, id);
    }

    /**
     * Adds identity. Certificates handled by a separate call to
     * addUserCert()
     */
    public void addUser(IUser identity) throws EUsrGrpException {
        User id = (User) identity;

        if (id == null) {
            throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_ADD_USER_FAIL"));
        }

        if (id.getUserID() == null) {
            throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_ADD_USER_FAIL_NO_UID"));
        }

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

        String oc[] = new String[oclist.size()];
        oc = oclist.toArray(oc);

        attrs.add(new LDAPAttribute(OBJECTCLASS_ATTR, oc));
        attrs.add(new LDAPAttribute("uid", id.getUserID()));
        attrs.add(new LDAPAttribute("sn", id.getFullName()));
        attrs.add(new LDAPAttribute("cn", id.getFullName()));
        attrs.add(new LDAPAttribute("mail", id.getEmail()));

        if (id.getPhone() != null) {
            // DS syntax checking requires a value for PrintableString syntax
            if (!id.getPhone().equals("")) {
                attrs.add(new LDAPAttribute("telephonenumber", id.getPhone()));
            }
        }

        attrs.add(new LDAPAttribute("userpassword",
                id.getPassword()));

        if (id.getUserType() != null) {
            // DS syntax checking requires a value for Directory String syntax
            // but usertype is a MUST attribute, so we need to add something here
            // if it is undefined.

            if (!id.getUserType().equals("")) {
                attrs.add(new LDAPAttribute("usertype", id.getUserType()));
            } else {
                attrs.add(new LDAPAttribute("usertype", "undefined"));
            }
        }

        if (id.getState() != null) {
            // DS syntax checking requires a value for Directory String syntax
            if (!id.getState().equals("")) {
                attrs.add(new LDAPAttribute("userstate", id.getState()));
            }
        }

        // TODO add audit logging for profile
        if (id.getTpsProfiles() != null) {
            List<String> profiles = id.getTpsProfiles();
            for (String profile: profiles) {
                attrs.add(new LDAPAttribute(LDAP_ATTR_PROFILE_ID, profile));
            }
        }

        LDAPEntry entry = new LDAPEntry("uid=" + LDAPUtil.escapeRDNValue(id.getUserID()) +
                "," + getUserBaseDN(), attrs);
        // for audit log
        SessionContext sessionContext = SessionContext.getContext();
        String adminId = (String) sessionContext.get(SessionContext.USER_ID);

        mLogger.log(ILogger.EV_AUDIT, ILogger.S_USRGRP,
                AuditFormat.LEVEL, AuditFormat.ADDUSERFORMAT,
                new Object[] { adminId, id.getUserID() }
                );

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            ldapconn.add(entry);

        } catch (LDAPException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_ADD_USER", e.toString()));
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_ADD_USER", e.toString()));
            throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_ADD_USER_FAIL"));

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }

    /**
     * adds a user certificate to user
     */
    public void addUserCert(IUser identity) throws EUsrGrpException {
        User user = (User) identity;

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
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_ADD_USER_CERT", e.toString()));
                throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_USR_CERT_ERROR"));
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

                mLogger.log(ILogger.EV_AUDIT, ILogger.S_USRGRP,
                        AuditFormat.LEVEL, AuditFormat.ADDUSERCERTFORMAT,
                        new Object[] { adminId, user.getUserID(),
                                cert[0].getSubjectDN().toString(),
                                cert[0].getSerialNumber().toString(16) }
                        );

            } catch (LDAPException e) {
                if (Debug.ON) {
                    e.printStackTrace();
                }
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_ADD_USER", e.toString()));
                throw LDAPExceptionConverter.toPKIException(e);

            } catch (ELdapException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_ADD_USER", e.toString()));
                throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_USR_CERT_ERROR"));

            } finally {
                if (ldapconn != null)
                    returnConn(ldapconn);
            }
        }

        return;
    }

    public void addCertSubjectDN(IUser identity) throws EUsrGrpException {
        User user = (User) identity;

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

                mLogger.log(ILogger.EV_AUDIT, ILogger.S_USRGRP,
                        AuditFormat.LEVEL, AuditFormat.ADDCERTSUBJECTDNFORMAT,
                        new Object[] { adminId, user.getUserID(),
                                cert[0].getSubjectDN().toString()}
                        );

            } catch (LDAPException e) {
                if (Debug.ON) {
                    e.printStackTrace();
                }
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_ADD_USER", e.toString()));
                throw LDAPExceptionConverter.toPKIException(e);

            } catch (ELdapException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_ADD_USER", e.toString()));
                throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_USR_CERT_ERROR"));

            } finally {
                if (ldapconn != null)
                    returnConn(ldapconn);
            }
        }

        return;
    }

    public void removeCertSubjectDN(IUser identity) throws EUsrGrpException {
        User user = (User) identity;

        if (user == null) {
            CMS.debug("removeCertSubjectDN: null user passed in");
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

                mLogger.log(ILogger.EV_AUDIT, ILogger.S_USRGRP,
                        AuditFormat.LEVEL, AuditFormat.REMOVECERTSUBJECTDNFORMAT,
                        new Object[] { adminId, user.getUserID(),
                                cert[0].getSubjectDN().toString() }
                        );

            } catch (LDAPException e) {
                if (Debug.ON) {
                    e.printStackTrace();
                }
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_ADD_USER", e.toString()));
                throw LDAPExceptionConverter.toPKIException(e);

            } catch (ELdapException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_ADD_USER", e.toString()));
                throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_USR_CERT_ERROR"));

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
    public void removeUserCert(IUser identity) throws EUsrGrpException {
        User user = (User) identity;
        User ldapUser = null;

        if (user == null) {
            return;
        }

        // retrieve all certs of the user, then match the cert String for
        // removal
        ldapUser = (User) getUser(user.getUserID());

        if (ldapUser == null) {
            throw new ResourceNotFoundException(CMS.getUserMessage("CMS_USRGRP_USER_NOT_FOUND"));
        }

        X509Certificate[] certs = ldapUser.getX509Certificates();

        if (certs == null) {
            throw new ResourceNotFoundException(CMS.getUserMessage("CMS_USRGRP_CERT_NOT_FOUND"));
        }

        String delCertdn = user.getCertDN();

        if (delCertdn == null) {
            throw new ResourceNotFoundException(CMS.getUserMessage("CMS_USRGRP_CERT_NOT_FOUND"));
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
                        CMS.debug("removeUserCert: No attribute "+LDAP_ATTR_CERTDN+" in entry "+dn);
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

                mLogger.log(ILogger.EV_AUDIT,
                        ILogger.S_USRGRP,
                        AuditFormat.LEVEL,
                        AuditFormat.REMOVEUSERCERTFORMAT,
                        new Object[] { adminId, user.getUserID(),
                                certs[0].getSubjectDN().toString(),
                                certs[i].getSerialNumber().toString(16) }
                        );

            } catch (CertificateEncodingException e) {
                throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_USR_CERT_ERROR"));

            } catch (LDAPException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_REMOVE_USER", e.toString()));
                throw LDAPExceptionConverter.toPKIException(e);

            } catch (ELdapException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_REMOVE_USER", e.toString()));
                throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_USR_CERT_ERROR"));

            } finally {
                if (ldapconn != null)
                    returnConn(ldapconn);
            }
        }

        if (certCount == 0) {
            throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_CERT_NOT_FOUND"));
        }
    }

    public void addUserToGroup(IGroup grp, String userid)
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
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_ADD_USER_TO_GROUP", e.toString()));
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_ADD_USER_TO_GROUP", e.toString()));

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }

    public void removeUserFromGroup(IGroup grp, String userid)
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
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_REMOVE_USER_FROM_GROUP", e.toString()));
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_REMOVE_USER_FROM_GROUP", e.toString()));

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

            mLogger.log(ILogger.EV_AUDIT, ILogger.S_USRGRP,
                    AuditFormat.LEVEL, AuditFormat.REMOVEUSERFORMAT,
                    new Object[] { adminId, userid }
                    );

        } catch (LDAPException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_REMOVE_USER", e.toString()));
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_REMOVE_USER", e.toString()));

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }


    /**
     * modifies user attributes. Certs are handled separately
     */
    public void modifyUser(IUser identity) throws EUsrGrpException {
        User user = (User) identity;
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
                            CMS.debug("modifyUser: Error in deleting telephonenumber");
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
                            CMS.debug("modifyUser: Error in deleting userstate");
                            throw e;
                        }
                    }
                }
            }

            if (user.getTpsProfiles() != null) {
                // TODO add audit logging for profile

                // replace the objectclass in case tpsProfile is not present
                String oc[] = { "top", "person", "organizationalPerson",
                        "inetOrgPerson", "cmsuser", "tpsProfileID" };
                attrs.add(LDAPModification.REPLACE,
                        new LDAPAttribute(OBJECTCLASS_ATTR, oc));

                User ldapUser = (User) getUser(user.getUserID());
                List<String> oldProfiles = ldapUser.getTpsProfiles();
                List<String> profiles = user.getTpsProfiles();

                if (oldProfiles == null) {
                    for (String profile : profiles) {
                        attrs.add(LDAPModification.ADD,
                                new LDAPAttribute(LDAP_ATTR_PROFILE_ID, profile));
                    }
                } else {
                    for (String profile : profiles) {
                        boolean found = false;
                        for (String oldProfile : oldProfiles) {
                            if (profile.equals(oldProfile)) {
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            attrs.add(LDAPModification.ADD,
                                    new LDAPAttribute(LDAP_ATTR_PROFILE_ID, profile));
                        }
                    }

                    for (String oldProfile : oldProfiles) {
                        boolean found = false;
                        for (String profile : profiles) {
                            if (profile.equals(oldProfile)) {
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            attrs.add(LDAPModification.DELETE,
                                    new LDAPAttribute(LDAP_ATTR_PROFILE_ID, oldProfile));
                        }
                    }
                }
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

            mLogger.log(ILogger.EV_AUDIT, ILogger.S_USRGRP,
                    AuditFormat.LEVEL, AuditFormat.MODIFYUSERFORMAT,
                    new Object[] { adminId, user.getUserID() }
                    );

        } catch (LDAPException e) {
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            //e.printStackTrace();
            throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_MOD_USER_FAIL"));

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }

    protected Enumeration<IGroup> buildGroups(LDAPSearchResults res) throws EUsrGrpException {
        Vector<IGroup> v = new Vector<IGroup>();

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
    public Enumeration<IGroup> findGroups(String filter) throws EUsrGrpException {
        if (filter == null) {
            return null;
        }

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            LDAPSearchResults res =
                    ldapconn.search(getGroupBaseDN(), LDAPv2.SCOPE_SUB,
                            "(&(objectclass=groupofuniquenames)(cn=" + filter + "))",
                            null, false);

            return buildGroups(res);
        } catch (LDAPException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_FIND_GROUPS", e.toString()));
            return null;
        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_FIND_GROUPS", e.toString()));
            return null;
        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }

    public IGroup findGroup(String filter) throws EUsrGrpException {
        Enumeration<IGroup> groups = findGroups(filter);

        if (groups == null || !groups.hasMoreElements())
            return null;
        return groups.nextElement();
    }

    /**
     * List groups. more efficient than find Groups. only retrieves
     * group names and description.
     */
    public Enumeration<IGroup> listGroups(String filter) throws EUsrGrpException {
        if (filter == null) {
            return null;
        }

        LDAPConnection ldapconn = null;

        try {
            String attrs[] = new String[2];

            attrs[0] = "cn";
            attrs[1] = "description";

            ldapconn = getConn();
            LDAPSearchResults res =
                    ldapconn.search(getGroupBaseDN(), LDAPv2.SCOPE_SUB,
                            "(&(objectclass=groupofuniquenames)(cn=" + filter + "))",
                            attrs, false);

            return buildGroups(res);
        } catch (LDAPException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_LIST_GROUPS", e.toString()));
        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_LIST_GROUPS", e.toString()));
        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
        return null;
    }

    public Enumeration<IGroup> findGroupsByUser(String userDn) throws EUsrGrpException {
        if (userDn == null) {
            return null;
        }

        LDAPConnection ldapconn = null;

        try {
            String attrs[] = new String[2];

            attrs[0] = "cn";
            attrs[1] = "description";

            ldapconn = getConn();
            LDAPSearchResults res =
                    ldapconn.search(getGroupBaseDN(), LDAPv2.SCOPE_SUB,
                            "(&(objectclass=groupofuniquenames)(uniqueMember=" + LDAPUtil.escapeFilter(userDn) + "))",
                            attrs, false);

            return buildGroups(res);
        } catch (LDAPException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_LIST_GROUPS", e.toString()));
        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_LIST_GROUPS", e.toString()));
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
    protected IGroup buildGroup(LDAPEntry entry) throws EUsrGrpException {
        LDAPAttribute cn = entry.getAttribute("cn");
        if (cn == null) {
            throw new EUsrGrpException("Cannot build group. No Attribute cn in LDAP Entry " + entry.getDN());
        }
        String groupName = (String) cn.getStringValues().nextElement();
        IGroup grp = createGroup(this, groupName);

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
                        // later...
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_BUILD_GROUP", ex.toString()));
                    }
                }
            }
        }
        if (grp.getDescription() == null) {
            try {
                grp.set("description", ""); // safety net
            } catch (EBaseException ex) {
                // later...
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_BUILD_GROUP", ex.toString()));
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
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_BAD_GROUP_MEMBER", groupName, v));
            } else {
                grp.addMemberName(v.substring(v.indexOf('=') + 1, v.indexOf(',')));
            }
        }

        return grp;
    }

    protected IGroup createGroup(IUsrGrp scope, String id) {
        return new Group(scope, id);
    }

    /**
     * Retrieves a group from LDAP
     * NOTE - this takes just the group name.
     */
    public IGroup getGroupFromName(String name) {
        return getGroup("cn=" + LDAPUtil.escapeRDNValue(name) + "," + getGroupBaseDN());
    }

    /**
     * Retrieves a group from LDAP
     * NOTE - LH This takes a full LDAP DN.
     */
    public IGroup getGroup(String groupDN) {
        if (groupDN == null) {
            return null;
        }

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            // read the group object
            LDAPSearchResults res = ldapconn.search(groupDN,
                    LDAPConnection.SCOPE_BASE, "(objectclass=*)", null, false);
            Enumeration<IGroup> e = buildGroups(res);

            if (e == null || e.hasMoreElements() == false)
                return null;
            return e.nextElement();
        } catch (Exception e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_GET_GROUP", e.toString()));
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
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_IS_GROUP_PRESENT", e.toString()));
        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
        return false;
    }

    public boolean isMemberOf(String userid, String groupname) {
        try {
            IUser user = getUser(userid);
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
    public boolean isMemberOf(IUser id, String name) {
        if (id == null) {
            log(ILogger.LL_WARN, "isMemberOf(): id is null");
            return false;
        }

        if (name == null) {
            log(ILogger.LL_WARN, "isMemberOf(): name is null");
            return false;
        }

        Debug.trace("UGSubsystem.isMemberOf() using new lookup code");
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
            Debug.trace("authorization search base: " + basedn);
            Debug.trace("authorization search filter: " + filter);
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
            Debug.trace("authorization result: " + founduser);
        } catch (LDAPException e) {
            String errMsg =
                    "isMemberOfLdapGroup: could not find group " + groupname + ". Error " + e;
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                errMsg = "isMemberOfLdapGroup: " + "Internal DB is unavailable";
            }
            Debug.trace("authorization exception: " + errMsg);
            // too chatty in system log
            // log(ILogger.LL_FAILURE, errMsg);
        } catch (ELdapException e) {
            String errMsg =
                    "isMemberOfLdapGroup: Could not get connection to internaldb. Error " + e;
            Debug.trace("authorization exception: " + errMsg);
            log(ILogger.LL_FAILURE, errMsg);
        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
        return founduser;
    }

    /**
     * Adds a group of identities.
     */
    public void addGroup(IGroup group) throws EUsrGrpException {
        Group grp = (Group) group;

        if (grp == null) {
            return;
        }

        LDAPConnection ldapconn = null;

        try {
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            String oc[] = { "top", "groupOfUniqueNames" };

            attrs.add(new LDAPAttribute("objectclass", oc));
            attrs.add(new LDAPAttribute("cn", group.getGroupID()));
            attrs.add(new LDAPAttribute("description", group.getDescription()));
            Enumeration<String> e = grp.getMemberNames();

            if (e.hasMoreElements() == true) {
                LDAPAttribute attrMembers = new LDAPAttribute("uniquemember");

                while (e.hasMoreElements()) {
                    String name = e.nextElement();

                    // DOES NOT SUPPORT NESTED GROUPS...
                    attrMembers.addValue("uid=" + LDAPUtil.escapeRDNValue(name) + "," +
                            getUserBaseDN());
                }
                attrs.add(attrMembers);
            }
            LDAPEntry entry = new LDAPEntry("cn=" + LDAPUtil.escapeRDNValue(grp.getGroupID()) +
                    "," + getGroupBaseDN(), attrs);

            ldapconn = getConn();
            ldapconn.add(entry);

        } catch (LDAPException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_ADD_GROUP", e.toString()));
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_ADD_GROUP", e.toString()));
            throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_ADD_GROUP_FAIL"));

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
            log(ILogger.LL_WARN, "removing Certificate Server Administrators group is not allowed");
            throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_REMOVE_GROUP_FAIL"));
        }

        LDAPConnection ldapconn = null;

        try {
            ldapconn = getConn();
            ldapconn.delete("cn=" + LDAPUtil.escapeRDNValue(name) + "," + getGroupBaseDN());

        } catch (LDAPException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_REMOVE_GROUP", e.toString()));
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_REMOVE_GROUP", e.toString()));
            throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_REMOVE_GROUP_FAIL"));

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }

    public void modifyGroup(IGroup group) throws EUsrGrpException {
        Group grp = (Group) group;

        if (grp == null) {
            return;
        }

        LDAPConnection ldapconn = null;

        try {
            LDAPAttribute attrMembers = new LDAPAttribute("uniquemember");
            LDAPModificationSet mod = new LDAPModificationSet();

            String desc = grp.getDescription();

            if (desc != null) {
                mod.add(LDAPModification.REPLACE,
                        new LDAPAttribute("description", desc));
            }

            Enumeration<String> e = grp.getMemberNames();

            if (e.hasMoreElements() == true) {
                while (e.hasMoreElements()) {
                    String name = e.nextElement();

                    // DOES NOT SUPPORT NESTED GROUPS...
                    attrMembers.addValue("uid=" + LDAPUtil.escapeRDNValue(name) + "," +
                            getUserBaseDN());
                }
                mod.add(LDAPModification.REPLACE, attrMembers);
            } else {
                if (!grp.getName().equalsIgnoreCase(SUPER_CERT_ADMINS)) {
                    mod.add(LDAPModification.DELETE, attrMembers);
                } else {
                    // not allowed
                    throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_ILL_GRP_MOD"));
                }
            }

            ldapconn = getConn();
            ldapconn.modify("cn=" + LDAPUtil.escapeRDNValue(grp.getGroupID()) +
                    "," + getGroupBaseDN(), mod);

        } catch (LDAPException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_MODIFY_GROUP", e.toString()));
            throw LDAPExceptionConverter.toPKIException(e);

        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_MODIFY_GROUP", e.toString()));
            throw new EUsrGrpException(CMS.getUserMessage("CMS_USRGRP_MOD_GROUP_FAIL"));

        } finally {
            if (ldapconn != null)
                returnConn(ldapconn);
        }
    }

    /**
     * Evalutes the given context with the attribute
     * critieria.
     */
    public boolean evaluate(String type, IUser id,
            String op, String value) {
        if (op.equals("=")) {
            if (type.equalsIgnoreCase("user")) {
                if (isMatched(value, id.getName()))
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
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_USRGRP_CONVERT_UID", e.toString()));
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

    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_USRGRP,
                level, "UGSubsystem: " + msg);
    }

    public ICertUserLocator getCertUserLocator() {
        return new ExactMatchCertUserLocator();
    }
}
