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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.certsrv.publish.ILdapPublisher;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

/**
 * Interface for publishing a CA certificate to
 *
 * @version $Revision$, $Date$
 */
public class LdapCaCertPublisher
        implements ILdapPublisher, IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapCaCertPublisher.class);

    public static final String LDAP_CACERT_ATTR = "caCertificate;binary";
    public static final String LDAP_CA_OBJECTCLASS = "pkiCA";
    public static final String LDAP_ARL_ATTR = "authorityRevocationList;binary";
    public static final String LDAP_CRL_ATTR = "certificateRevocationList;binary";

    protected String mCaCertAttr = LDAP_CACERT_ATTR;
    protected String mCaObjectclass = LDAP_CA_OBJECTCLASS;
    protected String mObjAdded = "";
    protected String mObjDeleted = "";

    private boolean mInited = false;
    protected IConfigStore mConfig = null;

    /**
     * constructor constructs default values.
     */
    public LdapCaCertPublisher() {
    }

    @Override
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

    @Override
    public String getImplName() {
        return "LdapCaCertPublisher";
    }

    @Override
    public String getDescription() {
        return "LdapCaCertPublisher";
    }

    @Override
    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<String>();

        v.addElement("caCertAttr=" + mCaCertAttr);
        v.addElement("caObjectClass=" + mCaObjectclass);
        return v;
    }

    @Override
    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<String>();

        v.addElement("caCertAttr=" + mCaCertAttr);
        v.addElement("caObjectClass=" + mCaObjectclass);
        return v;
    }

    @Override
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    @Override
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
    @Override
    public void publish(LDAPConnection conn, String dn, Object certObj)
            throws ELdapException {
        if (conn == null) {
            logger.warn("LdapCaCertPublisher: no LDAP connection");
            return;
        }

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        PKISocketConfig socketConfig = cs.getSocketConfig();

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

                PKISocketFactory sslSocket;
                if (cert_nick != null) {
                    sslSocket = new PKISocketFactory(cert_nick);
                } else {
                    sslSocket = new PKISocketFactory(true);
                }
                sslSocket.init(socketConfig);

                String mgr_dn = mConfig.getString("bindDN", null);
                String mgr_pwd = mConfig.getString("bindPWD", null);

                altConn = new LdapBoundConnection(host, portVal,
                        version,
                        sslSocket, mgr_dn, mgr_pwd);
                conn = altConn;
            }
        } catch (LDAPException e) {
            logger.warn("LdapCaCertPublisher: Unable to create alt connection: " + e.getMessage(), e);
        } catch (EBaseException e) {
            logger.warn("LdapCaCertPublisher: Unable to create alt connection: " + e.getMessage(), e);
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
                logger.warn("publish: CA " + dn + " already has Cert");
            } else {
                /*
                 fix for 360458 - if no cert, use add, if has cert but
                 not equal, use replace
                 */
                if (certs == null) {
                    modSet.add(LDAPModification.ADD,
                            new LDAPAttribute(mCaCertAttr, certEnc));
                    logger.info("LdapCaCertPublisher: CA cert added");
                } else {
                    modSet.add(LDAPModification.REPLACE,
                            new LDAPAttribute(mCaCertAttr, certEnc));
                    logger.info("LdapCaCertPublisher: CA cert replaced");
                }
            }

            String[] oclist = mCaObjectclass.split(",");

            boolean attrsAdded = false;
            for (int i = 0; i < oclist.length; i++) {
                String oc = oclist[i].trim();
                boolean hasoc = LdapUserCertPublisher.StringValueExists(ocs, oc);
                if (!hasoc) {
                    logger.info("LdapCaCertPublisher: Adding CA objectclass " + oc + " to " + dn);
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
                        logger.info("LdapCaCertPublisher: Deleting CA objectclass " + deloc + " from " + dn);
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
                    logger.warn("LdapCaCertPublisher: Failure in updating mObjAdded and mObjDeleted", e);
                }
            }

            if (modSet.size() > 0)
                conn.modify(dn, modSet);
        } catch (CertificateEncodingException e) {
            logger.error(CMS.getLogMessage("PUBLISH_CANT_DECODE_CERT", dn), e);
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_GET_DER_ENCODED_CERT_FAILED", e.toString()), e);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                logger.error(CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"), e);
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()), e);
            } else {
                logger.error(CMS.getLogMessage("PUBLISH_PUBLISHER_EXCEPTION", "", e.toString()), e);
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_CACERT_ERROR", e.toString()), e);
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
    @Override
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
                logger.warn("unpublish: " + dn + " has not cert already");
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
                        logger.info("unpublish: deleting CA oc" + oc + " from " + dn);
                        modSet.add(LDAPModification.DELETE,
                                new LDAPAttribute("objectclass", oc));
                    }
                }
            }
            conn.modify(dn, modSet);
        } catch (CertificateEncodingException e) {
            logger.error("LdapCaCertPublisher: unpublish: Cannot decode cert for " + dn + ": " + e.getMessage(), e);
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_GET_DER_ENCODED_CERT_FAILED", e.toString()));
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                logger.error(CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"), e);
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()), e);
            } else {
                logger.error(CMS.getLogMessage("PUBLISH_UNPUBLISH_ERROR", e.toString()), e);
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_UNPUBLISH_CACERT_ERROR", e.toString()), e);
            }
        }
        return;
    }
}
