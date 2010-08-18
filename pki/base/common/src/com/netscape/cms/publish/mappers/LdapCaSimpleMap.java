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


import netscape.ldap.*;
import netscape.ldap.util.*;
import java.io.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import netscape.security.x509.*;
import netscape.security.util.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.publish.*;


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
public class LdapCaSimpleMap implements ILdapMapper, IExtendedPluginInfo {
    protected static final String PROP_DNPATTERN = "dnPattern";  
    protected static final String PROP_CREATECA = "createCAEntry";  
    protected static final String PROP_CA_V2 = "CAEntryV2";  
    protected String mDnPattern = null;
    protected boolean mCreateCAEntry = true;

    private ILogger mLogger = CMS.getLogger();
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
    public LdapCaSimpleMap(String dnPattern) {
        try {
            init(dnPattern);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", e.toString()));
        }
		
    }

    /**
     * constructor if initializing from config store.
     */
    public LdapCaSimpleMap() {
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String params[] = {
                "dnPattern;string;Describes how to form the Ldap Subject name in" +
                " the directory.  Example 1:  'uid=CertMgr, o=Fedora'.  Example 2:" +
                " 'uid=$req.HTTP_PARAMS.uid, E=$ext.SubjectAlternativeName.RFC822Name, ou=$subj.ou'. " + 
                "$req means: take the attribute from the request. " + 
                "$subj means: take the attribute from the certificate subject name. " + 
                "$ext means: take the attribute from the certificate extension",
                "createCAEntry;boolean;If checked, CA entry will be created automatically",
                "CAEntryV2;boolean;If checked, CA entry will be created using certificationAuthority-v2",
                IExtendedPluginInfo.HELP_TOKEN + ";configuration-ldappublish-mapper-casimplemapper",
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

        mCreateCAEntry = mConfig.getBoolean(PROP_CREATECA, true);
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
            String[] mReqAttrs = mPattern.getReqAttrs();
            String[] mCertAttrs = mPattern.getCertAttrs();
        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_DN_PATTERN_INIT", dnPattern, e.toString()));
            throw new EBaseException("falied to init with pattern " + 
                    dnPattern + " " + e);
        }

        mInited = true;
    }

    /**
     * Maps a X500 subject name to LDAP entry.
     * Uses DN pattern to form a DN for a LDAP base search.
     * 
     * @param conn	the LDAP connection.
     * @param obj   the object to map.
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
     * @param conn	the LDAP connection.
     * @param req  	the request to map.
     * @param obj   the object to map.
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
                log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_DN_NOT_FORMED"));
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

            log(ILogger.LL_INFO, "searching for dn: " + dn + " filter:"
                + filter + " scope: base");

            LDAPSearchResults results = 
                conn.search(dn, scope, filter, attrs, false);
            LDAPEntry entry = results.next();

            if (results.hasMoreElements()) {
                log(ILogger.LL_FAILURE, 
                    CMS.getLogMessage("PUBLISH_MORE_THAN_ONE_ENTRY", dn,
                        ((req == null) ? "" : req.getRequestId().toString()))); 
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_MORE_THAN_ONE_ENTRY", 
                            ((req == null) ? "" : req.getRequestId().toString()))); 
            }
            if (entry != null)
                return entry.getDN();
            else {
                log(ILogger.LL_FAILURE, 
                    CMS.getLogMessage("PUBLISH_ENTRY_NOT_FOUND", dn,
                        ((req == null) ? "" : req.getRequestId().toString())));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND",
                            "null entry"));
            }
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"));
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), "" + conn.getPort()));
            } else if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT && mCreateCAEntry) {
                try {
                    createCAEntry(conn, dn);
                    log(ILogger.LL_INFO, "CA Entry " + dn + " Created");
                    return dn;
                } catch (LDAPException e1) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_DN_MAP_EXCEPTION", dn, e1.toString()));
                    if (e1.getLDAPResultCode() == LDAPException.CONSTRAINT_VIOLATION) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_CA_ENTRY_NOT_CREATED"));
                    } else {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_CA_ENTRY_NOT_CREATED1"));
                    }
                    throw new
                        ELdapException(CMS.getUserMessage("CMS_LDAP_CREATE_CA_FAILED", dn));
                }
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_DN_MAP_EXCEPTION", dn, e.toString()));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND", e.toString()));
            }
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_EXCEPTION_CAUGHT", e.toString()));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND", e.toString()));
        }
    }

    private void createCAEntry(LDAPConnection conn, String dn)
        throws LDAPException {
        LDAPAttributeSet attrs = new LDAPAttributeSet();
        // OID 2.5.6.16
        String caOc[] = null;
        boolean isV2 = false;
        try {
          isV2 = mConfig.getBoolean(PROP_CA_V2, false);
        } catch (EBaseException e) {
          // do nothing; default false
        }
        if (isV2) {
          caOc = new String[] {"top", 
                "person", 
                "organizationalPerson", 
                "inetOrgPerson", 
                "certificationAuthority-v2"};
        } else {
          caOc = new String[] {"top", 
                "person", 
                "organizationalPerson", 
                "inetOrgPerson", 
                "certificationAuthority"};
        }
		   
        String oOc[] = {"top", 
                "organization"};
        String oiOc[] = {"top", 
                "organizationalunit"};
		   
        DN dnobj = new DN(dn);
        String attrval[] = dnobj.explodeDN(true);

        attrs.add(new LDAPAttribute("cn", attrval[0]));
        attrs.add(new LDAPAttribute("sn", attrval[0]));
        attrs.add(new LDAPAttribute("objectclass", caOc));
        attrs.add(new LDAPAttribute(
                "authorityRevocationList;binary", ""));
        attrs.add(new LDAPAttribute(
                "cACertificate;binary", ""));
        attrs.add(new LDAPAttribute(
                "certificateRevocationList;binary", ""));
        if (isV2) {
          attrs.add(new LDAPAttribute(
                "deltaRevocationList;binary", ""));
        }
        LDAPEntry entry = new LDAPEntry(dn, attrs);

        conn.add(entry);
    }

    /**
     * form a dn from component in the request and cert subject name
     * @param req The request
     * @param obj The certificate or crl
     */
    private String formDN(IRequest req, Object obj) throws EBaseException {
        X500Name subjectDN = null;
        CertificateExtensions certExt = null;

        try {
            X509Certificate cert = (X509Certificate) obj;

            subjectDN = 
                    (X500Name) ((X509Certificate) cert).getSubjectDN();

            CMS.debug("LdapCaSimpleMap: cert subject dn:" + subjectDN.toString());
            X509CertInfo info = (X509CertInfo)
                ((X509CertImpl) cert).get(
                    X509CertImpl.NAME + "." + X509CertImpl.INFO);

            certExt = (CertificateExtensions) info.get(
                        CertificateExtensions.NAME);
        } catch (java.security.cert.CertificateParsingException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_CANT_GET_EXT", e.toString()));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_CANT_GET_EXT", e.toString()));
        } catch (java.security.cert.CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_CANT_GET_EXT", e.toString()));
        } catch (ClassCastException e) {
            try {
                X509CRLImpl crl = (X509CRLImpl) obj;

                subjectDN = 
                        (X500Name) ((X509CRLImpl) crl).getIssuerDN();

                CMS.debug("LdapCaSimpleMap: crl issuer dn: " +
                    subjectDN.toString());
            }catch (ClassCastException ex) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_PUBLISH_OBJ_NOT_SUPPORTED",
                        ((req == null) ? "" : req.getRequestId().toString())));
                return null;
            }
        }
        try {
            String dn = mPattern.formDN(req, subjectDN, certExt);

            return dn;
        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("PUBLISH_CANT_FORM_DN",
                    ((req == null) ? "" : req.getRequestId().toString()), e.toString()));
            throw new EBaseException("falied to form dn for request: " +
                    ((req == null) ? "" : req.getRequestId().toString()) + " " + e);
        }
    }

    public String getImplName() {
        return "LdapCaSimpleMap";
    }

    public String getDescription() {
        return "LdapCaSimpleMap";
    }

    public Vector getDefaultParams() {
        Vector v = new Vector();

        v.addElement(PROP_DNPATTERN + "=");
        v.addElement(PROP_CREATECA + "=true");
        v.addElement(PROP_CA_V2 + "=false");
        return v;
    }

    public Vector getInstanceParams() {
        Vector v = new Vector();

        try {
            if (mDnPattern == null) {
                v.addElement(PROP_DNPATTERN + "=");
            }else {
                v.addElement(PROP_DNPATTERN + "=" +
                    mConfig.getString(PROP_DNPATTERN));
            }
            v.addElement(PROP_CREATECA + "=" + mConfig.getBoolean(PROP_CREATECA, true));
            v.addElement(PROP_CA_V2 + "=" + mConfig.getBoolean(PROP_CA_V2, false));
        } catch (Exception e) {
        }
        return v;
    }

    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_LDAP, level,
            "LdapCaSimpleMapper: " + msg);
    }

}

