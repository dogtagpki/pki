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

import java.util.Locale;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
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
 * module for publishing a cross certificate pair to ldap
 * crossCertificatePair attribute
 *
 * @version $Revision$, $Date$
 */
public class LdapCertificatePairPublisher
        implements ILdapPublisher, IExtendedPluginInfo {
    public static final String LDAP_CROSS_CERT_PAIR_ATTR = "crossCertificatePair;binary";
    public static final String LDAP_CA_OBJECTCLASS = "pkiCA";
    public static final String LDAP_ARL_ATTR = "authorityRevocationList;binary";
    public static final String LDAP_CRL_ATTR = "certificateRevocationList;binary";
    public static final String LDAP_CACERT_ATTR = "caCertificate;binary";

    protected String mCrossCertPairAttr = LDAP_CROSS_CERT_PAIR_ATTR;
    protected String mCaObjectclass = LDAP_CA_OBJECTCLASS;
    protected String mObjAdded = "";
    protected String mObjDeleted = "";

    private ILogger mLogger = CMS.getLogger();
    private boolean mInited = false;
    protected IConfigStore mConfig = null;

    /**
     * constructor constructs default values.
     */
    public LdapCertificatePairPublisher() {
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String s[] = {
                "crossCertPairAttr;string;Name of Ldap attribute in which to store cross certificates",
                "caObjectClass;string;The name of the objectclasses which should be " +
                        "added to this entry, if they do not already exist. This can be " +
                        "'certificationAuthority' (if using RFC 2256) or 'pkiCA' (if using RFC 4523)",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ldappublish-publisher-crosscertpairpublisher",
                IExtendedPluginInfo.HELP_TEXT +
                        ";This plugin knows how to publish the CA cert to " +
                        "'certificateAuthority' and 'pkiCA' -type entries"
            };

        return s;
    }

    public String getImplName() {
        return "LdapCertificatePairPublisher";
    }

    public String getDescription() {
        return "LdapCertificatePairPublisher";
    }

    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<String>();

        v.addElement("crossCertPairAttr=" + mCrossCertPairAttr);
        v.addElement("caObjectClass=" + mCaObjectclass);
        return v;
    }

    public Vector<String> getInstanceParamsWithExtras() {
        return getInstanceParams();
    }

    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<String>();

        v.addElement("crossCertPairAttr=" + mCrossCertPairAttr);
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
        mCrossCertPairAttr = mConfig.getString("crossCertPairAttr", LDAP_CROSS_CERT_PAIR_ATTR);
        mCaObjectclass = mConfig.getString("caObjectClass",
                    LDAP_CA_OBJECTCLASS);
        mObjAdded = mConfig.getString("caObjectClassAdded", "");
        mObjDeleted = mConfig.getString("caObjectClassDeleted", "");

        mInited = true;
    }

    // don't think anyone would ever use this but just in case.
    public LdapCertificatePairPublisher(String crossCertPairAttr, String caObjectclass) {
        mCrossCertPairAttr = crossCertPairAttr;
        mCaObjectclass = caObjectclass;
        mInited = true;
    }

    /**
     * Gets the Certificate Authority object class to convert to.
     */
    public String getCAObjectclass() {
        return mCaObjectclass;
    }

    /**
     * returns the cross cert pair attribute where it'll be published.
     */
    public String getXCertAttrName() {
        return mCrossCertPairAttr;
    }

    /**
     * publish a certificatePair
     * -should not be called from listeners.
     *
     * @param conn the LDAP connection
     * @param dn dn of the entry to publish the XcertificatePair
     * @param pair the Xcertificate bytes object.
     */
    public synchronized void publish(LDAPConnection conn, String dn, Object pair)
            throws ELdapException {
        publish(conn, dn, (byte[]) pair);
    }

    /**
     * publish a certificatePair
     * -should not be called from listeners.
     *
     * @param conn the LDAP connection
     * @param dn dn of the entry to publish the XcertificatePair
     * @param pair the cross cert bytes
     */
    public synchronized void publish(LDAPConnection conn, String dn,
            byte[] pair)
            throws ELdapException {

        if (conn == null) {
            log(ILogger.LL_INFO, "LdapCertificatePairPublisher: no LDAP connection");
            return;
        }

        try {
            mCrossCertPairAttr = mConfig.getString("crossCertPairAttr", LDAP_CROSS_CERT_PAIR_ATTR);
            mCaObjectclass = mConfig.getString("caObjectClass", LDAP_CA_OBJECTCLASS);
        } catch (EBaseException e) {
        }

        try {
            // search for attributes to determine if they exist
            LDAPSearchResults res =
                    conn.search(dn, LDAPv2.SCOPE_BASE, "(objectclass=*)",
                            new String[] { LDAP_CACERT_ATTR, LDAP_CRL_ATTR, LDAP_ARL_ATTR }, true);
            LDAPEntry entry = res.next();
            LDAPAttribute certs = entry.getAttribute(LDAP_CACERT_ATTR);
            LDAPAttribute arls = entry.getAttribute(LDAP_ARL_ATTR);
            LDAPAttribute crls = entry.getAttribute(LDAP_CRL_ATTR);

            // search for objectclass and crosscertpair attributes and values
            LDAPSearchResults res1 =
                    conn.search(dn, LDAPv2.SCOPE_BASE, "(objectclass=*)",
                            new String[] { "objectclass", mCrossCertPairAttr }, false);
            LDAPEntry entry1 = res1.next();
            LDAPAttribute ocs = entry1.getAttribute("objectclass");
            LDAPAttribute certPairs = entry1.getAttribute("crosscertificatepair;binary");

            LDAPModificationSet modSet = new LDAPModificationSet();

            boolean hasCert = LdapUserCertPublisher.ByteValueExists(certPairs, pair);
            if (LdapUserCertPublisher.ByteValueExists(certPairs, pair)) {
                CMS.debug("LdapCertificatePairPublisher: cross cert pair bytes exist in publishing directory, do not publish again.");
                return;
            }
            if (hasCert) {
                log(ILogger.LL_INFO, "publish: CA " + dn + " already has cross cert pair bytes");
            } else {
                modSet.add(LDAPModification.ADD,
                        new LDAPAttribute(mCrossCertPairAttr, pair));
                log(ILogger.LL_INFO, "cross cert pair published with dn=" + dn);
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
                        if (certs == null)
                            modSet.add(LDAPModification.ADD,
                                    new LDAPAttribute(LDAP_CACERT_ATTR, ""));
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
                        log(ILogger.LL_INFO, "deleting CRL objectclass " + deloc + " from " + dn);
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
            CMS.debug("LdapCertificatePairPublisher: in publish() just published");
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
                throw new ELdapException("error publishing cross cert pair:" + e.toString());
            }
        }
        return;
    }

    /**
     * unsupported
     */
    public void unpublish(LDAPConnection conn, String dn, Object certObj)
            throws ELdapException {
        CMS.debug("LdapCertificatePairPublisher: unpublish() is unsupported in this revision");
    }

    /**
     * handy routine for logging in this class.
     */
    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_LDAP, level,
                "LdapCertificatePairPublisher: " + msg);
    }

}
