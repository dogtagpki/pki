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
// package statement //
///////////////////////

package com.netscape.cms.publish.mappers;

///////////////////////
// import statements //
///////////////////////

/* cert server imports */
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Vector;

import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.ILdapMapper;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.logging.Logger;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;
import netscape.ldap.LDAPv3;
import netscape.ldap.util.DN;

//////////////////////
// class definition //
//////////////////////

/**
 * Maps a request to an entry in the LDAP server.
 * Takes a dnPattern to form the baseDN from the
 * request attributes and certificate subject name.
 * Does a base search for the entry in the directory
 * to publish the cert or crl. The restriction of
 * this mapper is that the ldap dn components must
 * be part of certificate subject name or request
 * attributes or constant. The difference of this
 * mapper and LdapSimpleMap is that if the ldap
 * entry is not found, it has the option to create
 * the ldap entry given the dn and attributes
 * formulated.
 *
 * @version $Revision$, $Date$
 */
public class LdapEnhancedMap
        implements ILdapMapper, IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapEnhancedMap.class);

    ////////////////////////
    // default parameters //
    ////////////////////////

    //////////////////////////////////////
    // local LdapEnhancedMap parameters //
    //////////////////////////////////////

    private boolean mInited = false;

    // the subject DN pattern
    protected MapDNPattern mPattern = null;

    // the list of request attriubutes to retrieve
    protected String[] mReqAttrs = null;

    // the list of cert attributes to retrieve
    protected String[] mCertAttrs = null;

    protected String[] mLdapValues = null;

    ////////////////////////////
    // ILdapMapper parameters //
    ////////////////////////////

    /* mapper plug-in fields */
    protected static final String PROP_DNPATTERN = "dnPattern";
    protected static final String PROP_CREATE = "createEntry";
    // the object class of the entry to be created. xxxx not done yet
    protected static final String PROP_OBJCLASS = "objectClass";
    // req/cert/ext attribute --> directory attribute table
    protected static final String PROP_ATTRNUM = "attrNum";
    protected static final String PROP_ATTR_NAME = "attrName";
    protected static final String PROP_ATTR_PATTERN = "attrPattern";

    /* mapper plug-in fields initialization values */
    private static final int DEFAULT_NUM_ATTRS = 1;

    /* Holds mapper plug-in fields accepted by this implementation.
     * This list is passed to the configuration console so configuration
     * for instances of this implementation can be configured through the
     * console.
     */
    private static Vector<String> defaultParams = new Vector<String>();

    static {
        defaultParams.addElement(PROP_DNPATTERN + "=");
        defaultParams.addElement(PROP_CREATE + "=true");
        defaultParams.addElement(PROP_ATTRNUM + "=" + DEFAULT_NUM_ATTRS);
        for (int i = 0; i < DEFAULT_NUM_ATTRS; i++) {
            defaultParams.addElement(PROP_ATTR_NAME + i + "=");
            defaultParams.addElement(PROP_ATTR_PATTERN + i + "=");
        }
    }

    /* mapper plug-in values */
    protected String mDnPattern = null;
    protected boolean mCreateEntry = true;
    private int mNumAttrs = DEFAULT_NUM_ATTRS;
    protected String[] mLdapNames = null;
    protected String[] mLdapPatterns = null;

    /* miscellaneous constants local to this mapper plug-in */
    // default dn pattern if left blank or not set in the config
    public static final String DEFAULT_DNPATTERN =
            "UID=$req.HTTP_PARAMS.UID, " +
                    "OU=people, O=$subj.o, C=$subj.c";
    private static final int MAX_ATTRS = 10;
    protected static final int DEFAULT_ATTRNUM = 1;

    /* miscellaneous variables local to this mapper plug-in */
    protected IConfigStore mConfig = null;
    protected AVAPattern[] mPatterns = null;

    ////////////////////////////////////
    // IExtendedPluginInfo parameters //
    ////////////////////////////////////

    ///////////////////////
    // Logger parameters //
    ///////////////////////

    private Logger mLogger = Logger.getLogger();

    /////////////////////
    // default methods //
    /////////////////////

    /**
     * Default constructor, initialization must follow.
     */
    public LdapEnhancedMap() {
    }

    ///////////////////////////////////
    // local LdapEnhancedMap methods //
    ///////////////////////////////////

    /**
     * common initialization routine.
     */
    protected void init(String dnPattern)
            throws EBaseException {
        if (mInited) {
            return;
        }

        mDnPattern = dnPattern;
        if (mDnPattern == null ||
                mDnPattern.length() == 0) {
            mDnPattern = DEFAULT_DNPATTERN;
        }

        try {
            mPattern = new MapDNPattern(mDnPattern);
        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("PUBLISH_DN_PATTERN_INIT",
                            dnPattern, e.toString()));
            throw new EBaseException(
                    "falied to init with pattern " +
                            dnPattern + " " + e);
        }

        mInited = true;
    }

    /**
     * form a dn from component in the request and cert subject name
     *
     * @param req The request
     * @param obj The certificate or crl
     */
    private String formDN(IRequest req, Object obj)
            throws EBaseException {
        CertificateExtensions certExt = null;
        X500Name subjectDN = null;

        try {
            X509Certificate cert = (X509Certificate) obj;
            subjectDN = (X500Name) cert.getSubjectDN();
            logger.debug("LdapEnhancedMap: cert subject dn:" + subjectDN);

            //certExt = (CertificateExtensions)
            //          ((X509CertImpl)cert).get(
            //              X509CertInfo.EXTENSIONS);
            X509CertInfo info = (X509CertInfo)
                    ((X509CertImpl) cert).get(
                            X509CertImpl.NAME +
                                    "." +
                                    X509CertImpl.INFO);

            certExt = (CertificateExtensions)
                    info.get(CertificateExtensions.NAME);
        } catch (java.security.cert.CertificateParsingException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("PUBLISH_CANT_GET_EXT", e.toString()));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("PUBLISH_CANT_GET_EXT", e.toString()));
        } catch (java.security.cert.CertificateException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("PUBLISH_CANT_GET_EXT", e.toString()));
        } catch (ClassCastException e) {

            try {
                X509CRLImpl crl = (X509CRLImpl) obj;
                subjectDN = (X500Name) crl.getIssuerDN();

                logger.warn("LdapEnhancedMap: crl issuer dn: " + subjectDN + ": " + e.getMessage(), e);
            } catch (ClassCastException ex) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("PUBLISH_PUBLISH_OBJ_NOT_SUPPORTED",
                                ((req == null) ? ""
                                        : req.getRequestId().toString())));
                return null;
            }
        }

        try {
            mLdapValues = new String[mNumAttrs];

            for (int i = 0; i < mNumAttrs; i++) {
                if (mPatterns[i] != null) {
                    mLdapValues[i] = mPatterns[i].formAVA(
                                req,
                                subjectDN,
                                certExt);
                }
            }

            String dn = mPattern.formDN(req, subjectDN, certExt);

            return dn;
        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("PUBLISH_CANT_FORM_DN",
                            ((req == null) ? ""
                                    : req.getRequestId().toString()), e.toString()));

            throw new EBaseException(
                    "failed to form dn for request: " +
                            ((req == null) ? ""
                                    : req.getRequestId().toString()) +
                            " " + e);
        }
    }

    private void createEntry(LDAPConnection conn, String dn)
            throws LDAPException {
        LDAPAttributeSet attrs = new LDAPAttributeSet();

        // OID 2.5.6.16
        String caOc[] = { "top",
                "person",
                "organizationalPerson",
                "inetOrgPerson" };

        DN dnobj = new DN(dn);
        String attrval[] = dnobj.explodeDN(true);

        attrs.add(new LDAPAttribute("cn", attrval[0]));
        attrs.add(new LDAPAttribute("sn", attrval[0]));
        attrs.add(new LDAPAttribute("objectclass", caOc));

        for (int i = 0; i < mNumAttrs; i++) {
            if (mLdapNames[i] != null &&
                    !mLdapNames[i].trim().equals("") &&
                    mLdapValues[i] != null &&
                    !mLdapValues[i].trim().equals("")) {
                attrs.add(new LDAPAttribute(mLdapNames[i],
                        mLdapValues[i]));
            }
        }

        LDAPEntry entry = new LDAPEntry(dn, attrs);

        conn.add(entry);
    }

    /////////////////////////
    // ILdapMapper methods //
    /////////////////////////

    /**
     * for initializing from config store.
     *
     * implementation for extended
     * ILdapPlugin interface method
     */
    public void init(IConfigStore config)
            throws EBaseException {
        mConfig = config;

        mDnPattern = mConfig.getString(PROP_DNPATTERN,
                    DEFAULT_DNPATTERN);

        mCreateEntry = mConfig.getBoolean(PROP_CREATE,
                    true);

        mNumAttrs = mConfig.getInteger(PROP_ATTRNUM,
                    0);

        mLdapNames = new String[mNumAttrs];

        mLdapPatterns = new String[mNumAttrs];

        mPatterns = new AVAPattern[mNumAttrs];
        for (int i = 0; i < mNumAttrs; i++) {
            mLdapNames[i] =
                    mConfig.getString(PROP_ATTR_NAME +
                            Integer.toString(i),
                            "");

            mLdapPatterns[i] =
                    mConfig.getString(PROP_ATTR_PATTERN +
                            Integer.toString(i),
                            "");

            if (mLdapPatterns[i] != null &&
                    !mLdapPatterns[i].trim().equals("")) {
                mPatterns[i] = new AVAPattern(mLdapPatterns[i]);
            }
        }

        init(mDnPattern);
    }

    /**
     * implementation for extended
     * ILdapPlugin interface method
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public String getImplName() {
        return "LdapEnhancedMap";
    }

    public String getDescription() {
        return "LdapEnhancedMap";
    }

    public Vector<String> getDefaultParams() {
        return defaultParams;
    }

    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<String>();

        try {
            if (mDnPattern == null) {
                v.addElement(PROP_DNPATTERN + "=");
            } else {
                v.addElement(PROP_DNPATTERN + "=" +
                        mConfig.getString(PROP_DNPATTERN));
            }

            v.addElement(PROP_CREATE + "=" +
                    mConfig.getBoolean(PROP_CREATE,
                            true));

            v.addElement(PROP_ATTRNUM + "=" +
                    mConfig.getInteger(PROP_ATTRNUM,
                            DEFAULT_NUM_ATTRS));

            for (int i = 0; i < mNumAttrs; i++) {
                if (mLdapNames[i] != null) {
                    v.addElement(PROP_ATTR_NAME + i +
                            "=" + mLdapNames[i]);
                } else {
                    v.addElement(PROP_ATTR_NAME + i +
                            "=");
                }

                if (mLdapPatterns[i] != null) {
                    v.addElement(PROP_ATTR_PATTERN + i +
                            "=" + mLdapPatterns[i]);
                } else {
                    v.addElement(PROP_ATTR_PATTERN + i +
                            "=");
                }
            }
        } catch (Exception e) {
        }

        return v;
    }

    /**
     * Maps an X500 subject name to an LDAP entry.
     * Uses DN pattern to form a DN for an LDAP base search.
     *
     * @param conn the LDAP connection.
     * @param obj the object to map.
     * @exception ELdapException if any LDAP exceptions occurred.
     */
    public String map(LDAPConnection conn, Object obj)
            throws ELdapException {
        return map(conn, null, obj);
    }

    /**
     * Maps an X500 subject name to an LDAP entry.
     * Uses DN pattern to form a DN for an LDAP base search.
     *
     * @param conn the LDAP connection.
     * @param req the request to map.
     * @param obj the object to map.
     * @exception ELdapException if any LDAP exceptions occurred.
     */
    public String map(LDAPConnection conn, IRequest req, Object obj)
            throws ELdapException {
        if (conn == null) {
            return null;
        }

        String dn = null;

        try {
            dn = formDN(req, obj);
            if (dn == null) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("PUBLISH_DN_NOT_FORMED"));

                String s1 = "";

                if (req != null)
                    s1 = req.getRequestId().toString();
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_NO_DN_MATCH", s1));
            }

            int scope = LDAPv2.SCOPE_BASE;
            String filter = "(objectclass=*)";

            // search for entry
            String[] attrs = new String[] { LDAPv3.NO_ATTRS };

            log(ILogger.LL_INFO,
                    "searching for dn: " +
                            dn + " filter:" +
                            filter + " scope: base");

            LDAPSearchResults results = conn.search(dn,
                    scope,
                    filter,
                    attrs,
                    false);

            LDAPEntry entry = results.next();

            if (results.hasMoreElements()) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("PUBLISH_MORE_THAN_ONE_ENTRY",
                                dn +
                                        ((req == null) ? ""
                                                : req.getRequestId().toString())));

                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_MORE_THAN_ONE_ENTRY",
                                ((req == null) ? ""
                                        : req.getRequestId().toString())));
            }

            if (entry != null) {
                return entry.getDN();
            } else {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("PUBLISH_ENTRY_NOT_FOUND",
                                dn +
                                        ((req == null) ? ""
                                                : req.getRequestId().toString())));

                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND",
                            "null entry"));
            }
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"));

                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()));
            } else if (e.getLDAPResultCode() ==
                    LDAPException.NO_SUCH_OBJECT && mCreateEntry) {

                try {
                    createEntry(conn, dn);

                    log(ILogger.LL_INFO,
                            "Entry " +
                                    dn +
                                    " Created");

                    return dn;
                } catch (LDAPException e1) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("PUBLISH_DN_MAP_EXCEPTION",
                                    dn,
                                    e.toString()));

                    log(ILogger.LL_FAILURE,
                            "Entry is not created. " +
                                    "This may because there are " +
                                    "entries in the directory " +
                                    "hierachy not exit.");

                    throw new ELdapException(
                            CMS.getUserMessage("CMS_LDAP_CREATE_ENTRY", dn));
                }
            } else {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("PUBLISH_DN_MAP_EXCEPTION",
                                dn,
                                e.toString()));

                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND", e.toString()));
            }
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("PUBLISH_EXCEPTION_CAUGHT",
                            e.toString()));

            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND", e.toString()));
        }
    }

    /////////////////////////////////
    // IExtendedPluginInfo methods //
    /////////////////////////////////

    public String[] getExtendedPluginInfo(Locale locale) {
        Vector<String> v = new Vector<String>();

        v.addElement(PROP_DNPATTERN +
                ";string;Describes how to form the Ldap " +
                "Subject name in the directory.  " +
                "Example 1:  'uid=CertMgr, o=Fedora'.  " +
                "Example 2:  'uid=$req.HTTP_PARAMS.uid, " +
                "E=$ext.SubjectAlternativeName.RFC822Name, " +
                "ou=$subj.ou'. " +
                "$req means: take the attribute from the " +
                "request. " +
                "$subj means: take the attribute from the " +
                "certificate subject name. " +
                "$ext means: take the attribute from the " +
                "certificate extension");
        v.addElement(PROP_CREATE +
                ";boolean;If checked, An entry will be " +
                "created automatically");
        v.addElement(PROP_ATTRNUM +
                ";string;How many attributes to add.");
        v.addElement(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-ldappublish-mapper-enhancedmapper");
        v.addElement(IExtendedPluginInfo.HELP_TEXT +
                ";Describes how to form the LDAP DN of the " +
                "entry to publish to");

        for (int i = 0; i < MAX_ATTRS; i++) {
            v.addElement(PROP_ATTR_NAME +
                    Integer.toString(i) +
                    ";string;" +
                    "The name of LDAP attribute " +
                    "to be added. e.g. mail");
            v.addElement(PROP_ATTR_PATTERN +
                    Integer.toString(i) +
                    ";string;" +
                    "How to create the LDAP attribute value. " +
                    "e.g. $req.HTTP_PARAMS.csrRequestorEmail, " +
                    "$subj.E or " +
                    "$ext.SubjectAlternativeName.RFC822Name");
        }

        String params[] =
                org.mozilla.jss.netscape.security.util.Utils.getStringArrayFromVector(v);

        return params;
    }

    ////////////////////
    // Logger methods //
    ////////////////////

    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_LDAP, level,
                "LdapEnhancedMapper: " + msg);
    }
}
