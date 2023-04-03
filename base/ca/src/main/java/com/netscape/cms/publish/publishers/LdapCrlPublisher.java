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

import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.Vector;

import org.dogtagpki.server.PKIClientSocketListener;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.certsrv.publish.Publisher;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPConstraints;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;

/**
 * For publishing master or global CRL.
 * Publishes (replaces) the CRL in the CA's LDAP entry.
 */
public class LdapCrlPublisher
        extends Publisher
        implements IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapCrlPublisher.class);

    protected ConfigStore mConfig;
    boolean mInited = false;

    public static final String LDAP_CACERT_ATTR = "caCertificate;binary";
    public static final String LDAP_ARL_ATTR = "authorityRevocationList;binary";
    public static final String LDAP_CRL_ATTR = "certificateRevocationList;binary";
    public static final String LDAP_CRL_OBJECTCLASS = "pkiCA,deltaCRL";

    protected String mCrlAttr = LDAP_CRL_ATTR;
    protected String mCrlObjectClass = LDAP_CRL_OBJECTCLASS;
    protected String mObjAdded = "";
    protected String mObjDeleted = "";
    protected int mLdapPublishTimelimit_ms = 0; // in millisecond

    /**
     * constructs ldap crl publisher with default values
     */
    public LdapCrlPublisher() {
    }

    @Override
    public String getImplName() {
        return "LdapCrlPublisher";
    }

    @Override
    public String getDescription() {
        return "LdapCrlPublisher";
    }

    @Override
    public String[] getExtendedPluginInfo() {
        String[] params = {
                "crlAttr;string;Name of Ldap attribute in which to store the CRL",
                "crlObjectClass;string;The name of the objectclasses which should be " +
                        "added to this entry, if they do not already exist. This can be a comma-" +
                        "separated list such as 'certificationAuthority,certificationAuthority-V2' " +
                        "(if using RFC 2256) or 'pkiCA, deltaCRL' (if using RFC 4523)",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ldappublish-publisher-crlpublisher",
                IExtendedPluginInfo.HELP_TEXT +
                        ";This plugin knows how to publish CRL's to " +
                        "'certificateAuthority' and 'pkiCA' -type entries"
            };

        return params;
    }

    @Override
    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<>();

        v.addElement("crlAttr=" + mCrlAttr);
        v.addElement("crlObjectClass=" + mCrlObjectClass);
        return v;
    }

    @Override
    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<>();

        v.addElement("crlAttr=" + mCrlAttr);
        v.addElement("crlObjectClass=" + mCrlObjectClass);
        return v;
    }

    @Override
    public ConfigStore getConfigStore() {
        return mConfig;
    }

    @Override
    public void init(ConfigStore config) throws EBaseException {
        if (mInited)
            return;
        mConfig = config;
        mCrlAttr = mConfig.getString("crlAttr", LDAP_CRL_ATTR);
        mCrlObjectClass = mConfig.getString("crlObjectClass",
                LDAP_CRL_OBJECTCLASS);
        mObjAdded = mConfig.getString("crlObjectClassAdded", "");
        mObjDeleted = mConfig.getString("crlObjectClassDeleted", "");
        Integer limit = mConfig.getInteger("ldapPublishTimeLimit", 0);
        mLdapPublishTimelimit_ms = limit.intValue();

        mInited = true;
    }

    public LdapCrlPublisher(String crlAttr, String crlObjectClass) {
        mCrlAttr = crlAttr;
        mCrlObjectClass = crlObjectClass;
    }

    /**
     * Gets the CA object class to convert to.
     */
    public String getCRLObjectclass() {
        return mCrlObjectClass;
    }

    /**
     * Replaces the CRL in the certificateRevocationList attribute.
     * CRL's are published as a DER encoded blob.
     */
    @Override
    public void publish(LDAPConnection conn, String dn, Object crlObj) throws ELdapException {

        if (conn == null) {
            logger.warn("LdapCrlPublisher: No LDAP connection");
            return;
        }

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();

        PKISocketConfig socketConfig = cs.getSocketConfig();
        PKIClientSocketListener socketListener = new PKIClientSocketListener();

        try {
            mCrlAttr = mConfig.getString("crlAttr", LDAP_CRL_ATTR);
            mCrlObjectClass = mConfig.getString("crlObjectClass", LDAP_CRL_OBJECTCLASS);
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

                PKISocketFactory sslSocket = new PKISocketFactory(true);
                sslSocket.setCMSEngine(engine);
                sslSocket.setClientCertNickname(cert_nick);
                sslSocket.addSocketListener(socketListener);
                sslSocket.init(socketConfig);

                String mgr_dn = mConfig.getString("bindDN", null);
                String mgr_pwd = mConfig.getString("bindPWD", null);

                altConn = new LdapBoundConnection(host, portVal,
                        version,
                        sslSocket, mgr_dn, mgr_pwd);
                conn = altConn;
            }
        } catch (LDAPException e) {
            logger.warn("LdapCrlPublisher: Failed to create alt connection " + e.getMessage(), e);
        } catch (EBaseException e) {
            logger.warn("LdapCrlPublisher: Failed to create alt connection " + e.getMessage(), e);
        }

        int orig_timelimit = 0;
        LDAPConstraints constraints = null;
        try {
            byte[] crlEnc = ((X509CRL) crlObj).getEncoded();
            logger.info("LdapCrlPublisher: Retrieving attributes from " + dn);

            /* search for attribute names to determine existence of attributes */
            LDAPSearchResults res = null;
            if (mCrlAttr.equals(LDAP_CRL_ATTR)) {
                res = conn.search(
                        dn,
                        LDAPv3.SCOPE_BASE,
                        "(objectclass=*)",
                        new String[] { LDAP_CACERT_ATTR, LDAP_ARL_ATTR },
                        true);
            } else {
                res = conn.search(
                        dn,
                        LDAPv3.SCOPE_BASE,
                        "(objectclass=*)",
                        new String[] { LDAP_CRL_ATTR, LDAP_CACERT_ATTR, LDAP_ARL_ATTR },
                        true);
            }

            LDAPEntry entry = res.next();
            LDAPAttribute crls = entry.getAttribute(LDAP_CRL_ATTR);
            LDAPAttribute certs = entry.getAttribute(LDAP_CACERT_ATTR);
            LDAPAttribute arls = entry.getAttribute(LDAP_ARL_ATTR);

            logger.info("LdapCrlPublisher: Retrieving object classes from " + dn);
            /* get object class values */
            LDAPSearchResults res1 = conn.search(
                    dn,
                    LDAPv3.SCOPE_BASE,
                    "(objectclass=*)",
                    new String[] { "objectclass" },
                    false);

            LDAPEntry entry1 = res1.next();
            LDAPAttribute ocs = entry1.getAttribute("objectclass");

            LDAPModificationSet modSet = new LDAPModificationSet();

            String[] oclist = mCrlObjectClass.split(",");
            boolean attrsAdded = false;

            for (int i = 0; i < oclist.length; i++) {
                String oc = oclist[i].trim();

                boolean hasoc = LdapUserCertPublisher.StringValueExists(ocs, oc);

                if (!hasoc) {
                    logger.info("LdapCrlPublisher: Adding objectclass " + oc);
                    modSet.add(LDAPModification.ADD, new LDAPAttribute("objectclass", oc));

                    if ((!attrsAdded) && oc.equalsIgnoreCase("certificationAuthority")) {

                        // add MUST attributes
                        if (arls == null) {
                            logger.info("LdapCrlPublisher: Adding attribute " + LDAP_ARL_ATTR);
                            modSet.add(LDAPModification.ADD, new LDAPAttribute(LDAP_ARL_ATTR, ""));
                        }

                        if (certs == null) {
                            logger.info("LdapCrlPublisher: Adding attribute " + LDAP_CACERT_ATTR);
                            modSet.add(LDAPModification.ADD, new LDAPAttribute(LDAP_CACERT_ATTR, ""));
                        }

                        if (crls == null && !mCrlAttr.equals(LDAP_CRL_ATTR)) {
                            logger.info("LdapCrlPublisher: Adding attribute " + LDAP_CRL_ATTR);
                            modSet.add(LDAPModification.ADD, new LDAPAttribute(LDAP_CRL_ATTR, ""));
                        }

                        attrsAdded = true;
                    }
                }
            }

            logger.info("LdapCrlPublisher: Replacing attribute " + mCrlAttr);
            modSet.add(LDAPModification.REPLACE, new LDAPAttribute(mCrlAttr, crlEnc));

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
                        logger.info("LdapCrlPublisher: Deleting objectclass " + deloc);
                        modSet.add(LDAPModification.DELETE, new LDAPAttribute("objectclass", deloc));
                    }
                }
            }

            // reset mObjAdded and mObjDeleted, if needed
            if ((!mObjAdded.equals("")) || (!mObjDeleted.equals(""))) {
                mObjAdded = "";
                mObjDeleted = "";
                mConfig.putString("crlObjectClassAdded", "");
                mConfig.putString("crlObjectClassDeleted", "");
                try {
                    mConfig.commit(false);
                } catch (Exception e) {
                    logger.warn("LdapCrlPublisher: Unable to update mObjAdded and mObjDeleted", e);
                }
            }

            constraints = conn.getConstraints();
            if (constraints != null) {
                logger.debug("CRLDEBUG - setting publishing timelimit on conn to: " + String.valueOf(mLdapPublishTimelimit_ms));
                orig_timelimit = constraints.getTimeLimit();
                constraints.setTimeLimit(mLdapPublishTimelimit_ms);
                conn.setConstraints(constraints);
            } else {
                logger.debug("CRLDEBUG - constraints not set");
            }

            logger.info("LdapCrlPublisher: Modifying " + dn);
            conn.modify(dn, modSet);

        } catch (CRLException e) {
            logger.error(CMS.getLogMessage("PUBLISH_PUBLISH_ERROR", e.toString()), e);
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_CRL_ERROR", e.toString()), e);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                logger.error(CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"), e);
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()), e);
            }
            logger.error(CMS.getLogMessage("PUBLISH_PUBLISH_ERROR", e.toString()), e);
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_CRL_ERROR", e.toString()), e);
        } finally {
            // Reset original timelimit
            if (constraints != null) {
                logger.debug("CRLDEBUG - resetting original timelimit on conn to: " + String.valueOf(orig_timelimit));
                constraints.setTimeLimit(orig_timelimit);
                conn.setConstraints(constraints);
            }
            if (altConn != null) {
                try {
                    altConn.disconnect();
                } catch (LDAPException e) {
                    // safely ignored
                }
            }
        }
    }

    /**
     * There shouldn't be a need to call this.
     * CRLs are always replaced but this is implemented anyway in case
     * there is ever a reason to remove a global CRL.
     */
    @Override
    public void unpublish(LDAPConnection conn, String dn, Object crlObj)
            throws ELdapException {
        try {
            byte[] crlEnc = ((X509CRL) crlObj).getEncoded();

            try {
                mCrlAttr = mConfig.getString("crlAttr", LDAP_CRL_ATTR);
                mCrlObjectClass = mConfig.getString("crlObjectClass", LDAP_CRL_OBJECTCLASS);
            } catch (EBaseException e) {
            }

            LDAPSearchResults res = conn.search(dn, LDAPv3.SCOPE_BASE,
                    "(objectclass=*)", new String[] { mCrlAttr, "objectclass" }, false);
            LDAPEntry e = res.next();
            LDAPAttribute crls = e.getAttribute(mCrlAttr);
            LDAPAttribute ocs = e.getAttribute("objectclass");

            LDAPModificationSet modSet = new LDAPModificationSet();

            boolean hasOC = false;
            boolean hasCRL =
                    LdapUserCertPublisher.ByteValueExists(crls, crlEnc);

            if (hasCRL) {
                modSet.add(LDAPModification.DELETE,
                        new LDAPAttribute(mCrlAttr, crlEnc));
            }

            String[] oclist = mCrlObjectClass.split(",");
            for (int i = 0; i < oclist.length; i++) {
                String oc = oclist[i].trim();
                if (LdapUserCertPublisher.StringValueExists(ocs, oc)) {
                    logger.info("unpublish: deleting CRL object class " + oc + " from " + dn);
                    modSet.add(LDAPModification.DELETE,
                            new LDAPAttribute("objectClass", oc));
                    hasOC = true;
                }
            }

            if (hasCRL || hasOC) {
                conn.modify(dn, modSet);
            } else {
                logger.info("unpublish: " + dn + " already has not CRL");
            }
        } catch (CRLException e) {
            logger.error(CMS.getLogMessage("PUBLISH_UNPUBLISH_ERROR", e.toString()), e);
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_CRL_ERROR", e.toString()), e);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                logger.error(CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"), e);
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()), e);
            }
            logger.error(CMS.getLogMessage("PUBLISH_UNPUBLISH_ERROR", e.toString()), e);
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_UNPUBLISH_CRL_ERROR", e.toString()), e);
        }
        return;
    }
}
