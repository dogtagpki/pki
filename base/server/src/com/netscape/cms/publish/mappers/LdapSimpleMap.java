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
package com.netscape.cms.publish.mappers;

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
import com.netscape.certsrv.publish.ILdapMapper;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;
import netscape.ldap.LDAPv3;

/**
 * Maps a request to an entry in the LDAP server.
 * Takes a dnPattern to form the baseDN from the request attributes
 * and certificate subject name.Do a base search for the entry
 * in the directory to publish the cert or crl.
 * The restriction of this mapper is that the ldap dn components must
 * be part of certificate subject name or request attributes or constant.
 *
 * @version $Revision$, $Date$
 */
public class LdapSimpleMap implements ILdapMapper, IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapSimpleMap.class);

    protected static final String PROP_DNPATTERN = "dnPattern";
    protected String mDnPattern = null;

    private boolean mInited = false;
    protected IConfigStore mConfig = null;

    /* the subject DN pattern */
    protected MapDNPattern mPattern = null;

    /* the list of request attriubutes to retrieve*/
    protected String[] mReqAttrs = null;

    /* the list of cert attriubutes to retrieve*/
    protected String[] mCertAttrs = null;

    /* default dn pattern if left blank or not set in the config */
    public static final String DEFAULT_DNPATTERN =
            "UID=$req.HTTP_PARAMS.UID,  OU=people, O=$subj.o, C=$subj.c";

    /**
     * Constructor.
     *
     * @param dnPattern The base DN.
     */
    public LdapSimpleMap(String dnPattern) {
        try {
            init(dnPattern);
        } catch (EBaseException e) {
            logger.warn(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
        }

    }

    /**
     * constructor if initializing from config store.
     */
    public LdapSimpleMap() {
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String params[] = {
                "dnPattern;string;Describes how to form the Ldap Subject name in" +
                        " the directory.  Example 1:  'uid=CertMgr, o=Fedora'.  Example 2:" +
                        " 'uid=$req.HTTP_PARAMS.uid, E=$ext.SubjectAlternativeName.RFC822Name, ou=$subj.ou'. " +
                        "$req means: take the attribute from the request. " +
                        "$subj means: take the attribute from the certificate subject name. " +
                        "$ext means: take the attribute from the certificate extension",
                IExtendedPluginInfo.HELP_TOKEN + ";configuration-ldappublish-mapper-simplemapper",
                IExtendedPluginInfo.HELP_TEXT + ";Describes how to form the LDAP DN of the entry to publish to"
            };

        return params;
    }

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * for initializing from config store.
     */
    public void init(IConfigStore config)
            throws EBaseException {
        mConfig = config;
        String dnPattern = mConfig.getString(PROP_DNPATTERN);

        init(dnPattern);
    }

    /**
     * common initialization routine.
     */
    protected void init(String dnPattern)
            throws EBaseException {
        if (mInited)
            return;

        mDnPattern = dnPattern;
        if (mDnPattern == null || mDnPattern.length() == 0)
            mDnPattern = DEFAULT_DNPATTERN;
        try {
            mPattern = new MapDNPattern(mDnPattern);
        } catch (ELdapException e) {
            logger.error(CMS.getLogMessage("PUBLISH_DN_PATTERN_INIT",
                    dnPattern, e.toString()), e);
            throw new EBaseException("falied to init with pattern " +
                    dnPattern + " " + e, e);
        }

        mInited = true;
    }

    /**
     * Maps a X500 subject name to LDAP entry.
     * Uses DN pattern to form a DN for a LDAP base search.
     *
     * @param conn the LDAP connection.
     * @param obj the object to map.
     * @exception ELdapException if any LDAP exceptions occured.
     */
    public String map(LDAPConnection conn, Object obj)
            throws ELdapException {
        return map(conn, null, obj);
    }

    /**
     * Maps a X500 subject name to LDAP entry.
     * Uses DN pattern to form a DN for a LDAP base search.
     *
     * @param conn the LDAP connection.
     * @param req the request to map.
     * @param obj the object to map.
     * @exception ELdapException if any LDAP exceptions occured.
     */
    public String map(LDAPConnection conn, IRequest req, Object obj)
            throws ELdapException {
        if (conn == null)
            return null;
        String dn = null;

        try {
            dn = formDN(req, obj);
            if (dn == null) {
                logger.error(CMS.getLogMessage("PUBLISH_DN_NOT_FORMED"));
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

            logger.info("LdapSimpleMap: searching for dn: " + dn + " filter: " + filter + " scope: base");

            LDAPSearchResults results =
                    conn.search(dn, scope, filter, attrs, false);
            LDAPEntry entry = results.next();

            if (results.hasMoreElements()) {
                logger.error(CMS.getLogMessage("PUBLISH_MORE_THAN_ONE_ENTRY", dn, ((req == null) ? "" :
                        req.getRequestId().toString())));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_MORE_THAN_ONE_ENTRY",
                            ((req == null) ? "" : req.getRequestId().toString())));
            }
            if (entry != null)
                return entry.getDN();
            else {
                logger.error(CMS.getLogMessage("PUBLISH_ENTRY_NOT_FOUND", dn, ((req == null) ? "" : req.getRequestId().toString())));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND", "null entry"));
            }
        } catch (ELdapException e) {
            throw e;
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                logger.error(CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"), e);
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()), e);
            } else {
                logger.error(CMS.getLogMessage("PUBLISH_DN_MAP_EXCEPTION", "", e.toString()), e);
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND", e.toString()), e);
            }
        } catch (EBaseException e) {
            logger.error(CMS.getLogMessage("PUBLISH_EXCEPTION_CAUGHT", e.toString()), e);
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND", e.toString()), e);
        }
    }

    /**
     * form a dn from component in the request and cert subject name
     *
     * @param req The request
     * @param obj The certificate or crl
     */
    private String formDN(IRequest req, Object obj) throws
            EBaseException, ELdapException {
        X500Name subjectDN = null;
        CertificateExtensions certExt = null;

        try {
            X509Certificate cert = (X509Certificate) obj;
            subjectDN = (X500Name) cert.getSubjectDN();

            logger.debug("LdapSimpleMap: cert subject dn:" + subjectDN);
            //certExt = (CertificateExtensions)
            //        ((X509CertImpl)cert).get(X509CertInfo.EXTENSIONS);
            X509CertInfo info = (X509CertInfo)
                    ((X509CertImpl) cert).get(
                            X509CertImpl.NAME + "." + X509CertImpl.INFO);

            certExt = (CertificateExtensions) info.get(
                        CertificateExtensions.NAME);
        } catch (java.security.cert.CertificateParsingException e) {
            logger.warn(CMS.getLogMessage("PUBLISH_CANT_GET_EXT", e.toString()), e);
        } catch (IOException e) {
            logger.warn(CMS.getLogMessage("PUBLISH_CANT_GET_EXT", e.toString()), e);
        } catch (java.security.cert.CertificateException e) {
            logger.warn(CMS.getLogMessage("PUBLISH_CANT_GET_EXT", e.toString()), e);
        } catch (ClassCastException e) {
            try {
                X509CRLImpl crl = (X509CRLImpl) obj;
                subjectDN = (X500Name) crl.getIssuerDN();

                logger.warn("LdapSimpleMap: crl issuer dn: " + subjectDN + ": " + e.getMessage(), e);
            } catch (ClassCastException ex) {
                logger.warn(CMS.getLogMessage("PUBLISH_PUBLISH_OBJ_NOT_SUPPORTED",
                                ((req == null) ? "" : req.getRequestId().toString())), ex);
                return null;
            }
        }
        try {
            String dn = mPattern.formDN(req, subjectDN, certExt);

            return dn;
        } catch (ELdapException e) {
            logger.warn(CMS.getLogMessage("PUBLISH_CANT_FORM_DN",
                    ((req == null) ? "" : req.getRequestId().toString()), e.toString()), e);
            throw e;
        }
    }

    public String getImplName() {
        return "LdapSimpleMap";
    }

    public String getDescription() {
        return "LdapSimpleMap";
    }

    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<String>();

        v.addElement(PROP_DNPATTERN + "=");
        return v;
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
        } catch (Exception e) {
        }
        return v;
    }
}
