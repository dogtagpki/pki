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
package com.netscape.cms.publish.publishers;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSSLSocketFactoryExt;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.ILdapPublisher;

/**
 * Interface for publishing a CA certificate to
 *
 * @version $Revision$, $Date$
 */
public class LdapCaCertPublisher
        implements ILdapPublisher, IExtendedPluginInfo {
    public static final String LDAP_CACERT_ATTR = "caCertificate;binary";
    public static final String LDAP_CA_OBJECTCLASS = "pkiCA";
    public static final String LDAP_ARL_ATTR = "authorityRevocationList;binary";
    public static final String LDAP_CRL_ATTR = "certificateRevocationList;binary";

    protected String mCaCertAttr = LDAP_CACERT_ATTR;
    protected String mCaObjectclass = LDAP_CA_OBJECTCLASS;
    protected String mObjAdded = "";
    protected String mObjDeleted = "";

    private ILogger mLogger = CMS.getLogger();
    private boolean mInited = false;
    protected IConfigStore mConfig = null;

    /**
     * constructor constructs default values.
     */
    public LdapCaCertPublisher() {
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String s[] = {
                "caCertAttr;string;Name of Ldap attribute in which to store certificate",
                "caObjectClass;string;The name of the objectclasses which should be " +
                        "added to this entry, if they do not already exist. This can be " +
                        "'certificationAuthority' (if using RFC 2256) or 'pkiCA' (if using RFC 4523)",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ldappublish-publisher-cacertpublisher",
                IExtendedPluginInfo.HELP_TEXT +
                        ";This plugin knows how to publish the CA cert to " +
                        "'certificateAuthority' and 'pkiCA' -type entries"
            };

        return s;
    }

    public String getImplName() {
        return "LdapCaCertPublisher";
    }

    public String getDescription() {
        return "LdapCaCertPublisher";
    }

    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<String>();

        v.addElement("caCertAttr=" + mCaCertAttr);
        v.addElement("caObjectClass=" + mCaObjectclass);
        return v;
    }

    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<String>();

        v.addElement("caCertAttr=" + mCaCertAttr);
        v.addElement("caObjectClass=" + mCaObjectclass);
        return v;
    }

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public void init(IConfigStore config)
            throws EBaseException {
        if (mInited)
            return;
        mConfig = config;
        mCaCertAttr = mConfig.getString("caCertAttr", LDAP_CACERT_ATTR);
        mCaObjectclass = mConfig.getString("caObjectClass",
                    LDAP_CA_OBJECTCLASS);
        mObjAdded = mConfig.getString("caObjectClassAdded", "");
        mObjDeleted = mConfig.getString("caObjectClassDeleted", "");
        mInited = true;
    }

    // don't think anyone would ever use this but just in case.
    public LdapCaCertPublisher(String caCertAttr, String caObjectclass) {
        mCaCertAttr = caCertAttr;
        mCaObjectclass = caObjectclass;
        mInited = true;
    }

    /**
     * Gets the CA object class to convert to.
     */
    public String getCAObjectclass() {
        return mCaObjectclass;
    }

    /**
     * returns the ca cert attribute where it'll be published.
     */
    public String getCaCertAttrName() {
        return mCaCertAttr;
    }

    /**
     * publish a CA certificate
     * Adds the cert to the multi-valued certificate attribute as a
     * DER encoded binary blob. Does not check if cert already exists.
     * Converts the class to certificateAuthority.
     *
     * @param conn the LDAP connection
     * @param dn dn of the entry to publish the certificate
     * @param certObj the certificate object.
     */
    public void publish(LDAPConnection conn, String dn, Object certObj)
            throws ELdapException {
        if (conn == null) {
            log(ILogger.LL_INFO, "LdapCaCertPublisher: no LDAP connection");
            return;
        }

        try {
            mCaCertAttr = mConfig.getString("caCertAttr", LDAP_CACERT_ATTR);
            mCaObjectclass = mConfig.getString("caObjectClass", LDAP_CA_OBJECTCLASS);
        } catch (EBaseException e) {
        }

        // Bugscape #56124 - support multiple publishing directory
        // see if we should create local connection
        LDAPConnection altConn = null;
        try {
            String host = mConfig.getString("host", null);
            String port = mConfig.getString("port", null);
            if (host != null && port != null) {
                int portVal = Integer.parseInt(port);
                int version = Integer.parseInt(mConfig.getString("version", "2"));
                String cert_nick = mConfig.getString("clientCertNickname", null);
                LDAPSSLSocketFactoryExt sslSocket = null;
                if (cert_nick != null) {
                    sslSocket = CMS.getLdapJssSSLSocketFactory(cert_nick);
                }
                String mgr_dn = mConfig.getString("bindDN", null);
                String mgr_pwd = mConfig.getString("bindPWD", null);

                altConn = CMS.getBoundConnection(host, portVal,
                        version,
                        sslSocket, mgr_dn, mgr_pwd);
                conn = altConn;
            }
        } catch (LDAPException e) {
            CMS.debug("Failed to create alt connection " + e);
        } catch (EBaseException e) {
            CMS.debug("Failed to create alt connection " + e);
        }

        if (!(certObj instanceof X509Certificate))
            throw new IllegalArgumentException("Illegal arg to publish");

        X509Certificate cert = (X509Certificate) certObj;

        try {
            byte[] certEnc = cert.getEncoded();

            /* search for attribute names to determine existence of attributes */
            LDAPSearchResults res =
                    conn.search(dn, LDAPv2.SCOPE_BASE, "(objectclass=*)",
                            new String[] { LDAP_CRL_ATTR, LDAP_ARL_ATTR }, true);
            LDAPEntry entry = res.next();
            LDAPAttribute arls = entry.getAttribute(LDAP_ARL_ATTR);
            LDAPAttribute crls = entry.getAttribute(LDAP_CRL_ATTR);

            /* search for objectclass and caCert values */
            LDAPSearchResults res1 =
                    conn.search(dn, LDAPv2.SCOPE_BASE, "(objectclass=*)",
                            new String[] { "objectclass", mCaCertAttr }, false);
            LDAPEntry entry1 = res1.next();
            LDAPAttribute ocs = entry1.getAttribute("objectclass");
            LDAPAttribute certs = entry1.getAttribute(mCaCertAttr);

            boolean hasCert =
                    LdapUserCertPublisher.ByteValueExists(certs, certEnc);

            LDAPModificationSet modSet = new LDAPModificationSet();

            if (hasCert) {
                log(ILogger.LL_INFO, "publish: CA " + dn + " already has Cert");
            } else {
                /*
                 fix for 360458 - if no cert, use add, if has cert but
                 not equal, use replace
                 */
                if (certs == null) {
                    modSet.add(LDAPModification.ADD,
                            new LDAPAttribute(mCaCertAttr, certEnc));
                    log(ILogger.LL_INFO, "CA cert added");
                } else {
                    modSet.add(LDAPModification.REPLACE,
                            new LDAPAttribute(mCaCertAttr, certEnc));
                    log(ILogger.LL_INFO, "CA cert replaced");
                }
            }

            String[] oclist = mCaObjectclass.split(",");

            boolean attrsAdded = false;
            for (int i = 0; i < oclist.length; i++) {
                String oc = oclist[i].trim();
                boolean hasoc = LdapUserCertPublisher.StringValueExists(ocs, oc);
                if (!hasoc) {
                    log(ILogger.LL_INFO, "adding CA objectclass " + oc + " to " + dn);
                    modSet.add(LDAPModification.ADD,
                            new LDAPAttribute("objectclass", oc));

                    if ((!attrsAdded) && oc.equalsIgnoreCase("certificationAuthority")) {
                        // add MUST attributes
                        if (arls == null)
                            modSet.add(LDAPModification.ADD,
                                    new LDAPAttribute(LDAP_ARL_ATTR, ""));
                        if (crls == null)
                            modSet.add(LDAPModification.ADD,
                                    new LDAPAttribute(LDAP_CRL_ATTR, ""));
                        attrsAdded = true;
                    }
                }
            }

            // delete objectclasses that have been deleted from config
            String[] delList = mObjDeleted.split(",");
            if (delList.length > 0) {
                for (int i = 0; i < delList.length; i++) {
                    String deloc = delList[i].trim();
                    boolean hasoc = LdapUserCertPublisher.StringValueExists(ocs, deloc);
                    boolean match = false;
                    for (int j = 0; j < oclist.length; j++) {
                        if ((oclist[j].trim()).equals(deloc)) {
                            match = true;
                            break;
                        }
                    }
                    if (!match && hasoc) {
                        log(ILogger.LL_INFO, "deleting CA objectclass " + deloc + " from " + dn);
                        modSet.add(LDAPModification.DELETE,
                                new LDAPAttribute("objectclass", deloc));
                    }
                }
            }

            // reset mObjAdded and mObjDeleted, if needed
            if ((!mObjAdded.equals("")) || (!mObjDeleted.equals(""))) {
                mObjAdded = "";
                mObjDeleted = "";
                mConfig.putString("caObjectClassAdded", "");
                mConfig.putString("caObjectClassDeleted", "");
                try {
                    mConfig.commit(false);
                } catch (Exception e) {
                    log(ILogger.LL_INFO, "Failure in updating mObjAdded and mObjDeleted");
                }
            }

            if (modSet.size() > 0)
                conn.modify(dn, modSet);
        } catch (CertificateEncodingException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_CANT_DECODE_CERT", dn));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_GET_DER_ENCODED_CERT_FAILED", e.toString()));
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"));
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()));
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_PUBLISHER_EXCEPTION", "", e.toString()));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_CACERT_ERROR", e.toString()));
            }
        } finally {
            if (altConn != null) {
                try {
                    altConn.disconnect();
                } catch (LDAPException e) {
                    // safely ignored
                }
            }
        }

        return;
    }

    /**
     * deletes the certificate from CA's certificate attribute.
     * if it's the last cert will also remove the certificateAuthority
     * objectclass.
     */
    public void unpublish(LDAPConnection conn, String dn, Object certObj)
            throws ELdapException {
        if (!(certObj instanceof X509Certificate))
            throw new IllegalArgumentException("Illegal arg to publish");

        X509Certificate cert = (X509Certificate) certObj;

        try {
            mCaCertAttr = mConfig.getString("caCertAttr", LDAP_CACERT_ATTR);
            mCaObjectclass = mConfig.getString("caObjectClass", LDAP_CA_OBJECTCLASS);
        } catch (EBaseException e) {
        }

        try {
            byte[] certEnc = cert.getEncoded();

            LDAPSearchResults res =
                    conn.search(dn, LDAPv2.SCOPE_BASE, "(objectclass=*)",
                            new String[] { mCaCertAttr, "objectclass" }, false);

            LDAPEntry entry = res.next();
            LDAPAttribute certs = entry.getAttribute(mCaCertAttr);
            LDAPAttribute ocs = entry.getAttribute("objectclass");

            boolean hasCert =
                    LdapUserCertPublisher.ByteValueExists(certs, certEnc);

            if (!hasCert) {
                log(ILogger.LL_INFO, "unpublish: " + dn + " has not cert already");
                //throw new ELdapException(
                //		  LdapResources.ALREADY_UNPUBLISHED_1, dn);
                return;
            }

            LDAPModificationSet modSet = new LDAPModificationSet();

            modSet.add(LDAPModification.DELETE,
                    new LDAPAttribute(mCaCertAttr, certEnc));
            if (certs.size() == 1) {
                // if last ca cert, remove oc also.

                String[] oclist = mCaObjectclass.split(",");
                for (int i = 0; i < oclist.length; i++) {
                    String oc = oclist[i].trim();
                    boolean hasOC = LdapUserCertPublisher.StringValueExists(ocs, oc);
                    if (hasOC) {
                        log(ILogger.LL_INFO, "unpublish: deleting CA oc" + oc + " from " + dn);
                        modSet.add(LDAPModification.DELETE,
                                new LDAPAttribute("objectclass", oc));
                    }
                }
            }
            conn.modify(dn, modSet);
        } catch (CertificateEncodingException e) {
            CMS.debug("LdapCaCertPublisher: unpublish: Cannot decode cert for " + dn);
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_GET_DER_ENCODED_CERT_FAILED", e.toString()));
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"));
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()));
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_UNPUBLISH_ERROR", e.toString()));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_UNPUBLISH_CACERT_ERROR", e.toString()));
            }
        }
        return;
    }

    /**
     * handy routine for logging in this class.
     */
    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_LDAP, level,
                "LdapCaPublisher: " + msg);
    }

}
