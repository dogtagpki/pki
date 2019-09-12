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
package com.netscape.cmscore.cert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.cert.ICrossCertPairSubsystem;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.publish.IPublisherProcessor;
import com.netscape.certsrv.publish.IXcertPublisherProcessor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

/**
 * Subsystem for handling cross certificate pairing and publishing
 * Intended use:
 * <ul>
 * <li>when signing a subordinate CA cert which is intended to be part of the crossCertificatePair
 * <li>when this ca submits a request (with existing CA signing key material to another ca for cross-signing
 * </ul>
 * In both cases, administrator needs to "import" the crossSigned
 * certificates via the admin console. When importCert() is called,
 * the imported cert will be stored in the internal db
 * first until it's pairing cert shows up.
 * If it happens that the above two cases finds its pairing
 * cert already there, then a CertifiatePair is created and put
 * in the internal db "crosscertificatepair;binary" attribute
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class CrossCertPairSubsystem implements ICrossCertPairSubsystem {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CrossCertPairSubsystem.class);

    public static final String ID = "CrossCertPair";
    public static final String DN_XCERTS = "cn=crossCerts";
    public static final String LDAP_ATTR_CA_CERT = "caCertificate;binary";
    public static final String LDAP_ATTR_XCERT_PAIR = "crossCertificatePair;binary";
    protected static final String PROP_LDAP = "ldap";
    protected static final String PROP_BASEDN = "basedn";

    protected IConfigStore mConfig = null;
    protected LdapBoundConnFactory mLdapConnFactory = null;
    protected String mBaseDN = null;
    protected ICertificateAuthority mCa = null;
    protected IPublisherProcessor mPublisherProcessor = null;

    private String mId = ID;

    public CrossCertPairSubsystem() {
    }

    /**
     * Retrieves subsystem identifier.
     */
    public String getId() {
        return mId;
    }

    public void setId(String id) throws EBaseException {
        mId = id;
    }

    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {

        logger.debug("CrossCertPairSubsystem: initializing");

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        try {
            mConfig = config;
            synchronized (this) {
                mCa = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);
                mPublisherProcessor = mCa.getPublisherProcessor();
            }

            // initialize LDAP connection factory
            IConfigStore ldapConfig = mConfig.getSubStore(PROP_LDAP);

            if (ldapConfig == null) {
                logger.warn(CMS.getLogMessage("CMSCORE_DBS_CONF_ERROR", PROP_LDAP));
                return;
            }

            mBaseDN = ldapConfig.getString(PROP_BASEDN, null);

            mLdapConnFactory = new LdapBoundConnFactory("CrossCertPairSubsystem");

            if (mLdapConnFactory != null) {
                mLdapConnFactory.init(cs, ldapConfig, engine.getPasswordStore());
            } else {
                logger.warn(CMS.getLogMessage("CMSCORE_DBS_CONF_ERROR", PROP_LDAP));
                return;
            }

        } catch (EBaseException e) {
            logger.error("CrossCertPairSubsystem: Unable to initialize subsystem: " + e.getMessage(), e);
            throw e;
        }

        logger.debug("CrossCertPairSubsystem: initialization complete");
    }

    /**
     * "import" the CA cert cross-signed by another CA (potentially a
     * bridge CA) into internal ldap db.
     * the imported cert will be stored in the internal db
     * first until it's pairing cert shows up.
     * If it happens that it finds its pairing
     * cert already there, then a CertifiatePair is created and put
     * in the internal db "crosscertificatepair;binary" attribute
     *
     * @param certBytes cert in byte array to be imported
     */
    public void importCert(byte[] certBytes) throws EBaseException {
        logger.debug("CrossCertPairSubsystem: importCert(byte[])");
        X509Certificate cert = null;

        try {
            cert = byteArray2X509Cert(certBytes);
        } catch (CertificateException e) {
            throw new EBaseException("CrossCertPairSubsystem: importCert() failed:" + e.toString());

        }

        importCert(cert);
    }

    /**
     * "import" the CA cert cross-signed by another CA (potentially a
     * bridge CA) into internal ldap db.
     * the imported cert will be stored in the internal db
     * first until it's pairing cert shows up.
     * If it happens that it finds its pairing
     * cert already there, then a CertifiatePair is created and put
     * in the internal db "crosscertificatepair;binary" attribute
     *
     * @param certBytes cert in byte array to be imported
     */
    public synchronized void importCert(Object certObj) throws EBaseException {
        if (!(certObj instanceof X509Certificate))
            throw new IllegalArgumentException("Illegal arg to publish");

        logger.debug("CrossCertPairSubsystem: in importCert(Object)");
        X509Certificate cert = (X509Certificate) certObj;
        // check to see if this is a valid cross-signed ca cert:
        // 1. does cert2 share the same key pair as this CA's signing
        // cert
        // 2. does cert2's subject match this CA's subject?
        // 3. other valididity checks: is this a ca cert?  Is this
        // cert still valid?  If the issuer is not yet trusted, let it
        // be.

        // get certs from internal db to see if we find a pair
        LDAPConnection conn = null;

        try {
            conn = getConn();
            LDAPSearchResults res = conn.search(mBaseDN, LDAPv2.SCOPE_SUB,
                    DN_XCERTS, null, false);

            if (res.hasMoreElements()) {
                logger.info("CrossCertPairSubsystem: ldap search found " + DN_XCERTS);

                LDAPEntry entry = (LDAPEntry) res.nextElement();
                LDAPAttribute caCerts = entry.getAttribute(LDAP_ATTR_CA_CERT);
                LDAPAttribute certPairs = entry.getAttribute(LDAP_ATTR_XCERT_PAIR);

                if (caCerts == null) {
                    logger.debug("CrossCertPairSubsystem: no existing ca certs, just import");
                    addCAcert(conn, cert.getEncoded());
                    return;
                }

                @SuppressWarnings("unchecked")
                Enumeration<byte[]> en = caCerts.getByteValues();

                if ((en == null) || (en.hasMoreElements() == false)) {
                    logger.debug("CrossCertPairSubsystem: 1st potential xcert");
                    addCAcert(conn, cert.getEncoded());
                    logger.debug("CrossCertPairSubsystem: potential cross ca cert added to crossCerts entry successfully");
                    return;
                }
                byte[] val = null;
                boolean match = false;

                while (en.hasMoreElements()) {
                    val = en.nextElement();
                    logger.debug("CrossCertPairSubsystem: val =" + val.length);
                    if (val.length == 0) {
                        continue;
                    } else {
                        X509Certificate inCert = byteArray2X509Cert(val);

                        if (arePair(inCert, cert)) {
                            // found a pair,form xcert, write to
                            // crossCertificatePair attr, remove from
                            // caCertificate attr, and publish if so configured
                            logger.debug("CrossCertPairSubsystem: found a pair!");
                            CertificatePair cp = new
                                    //								CertificatePair(inCert.getEncoded(), cert.getEncoded());
                                    CertificatePair(inCert, cert);

                            addXCertPair(conn, certPairs, cp);
                            deleteCAcert(conn, inCert.getEncoded());
                            // found a match, get out
                            match = true;
                            break;
                        }
                    }
                } //while
                if (match == false) {
                    // don't find a pair, add it into
                    // caCertificate attr for later pairing
                    // opportunities
                    logger.debug("CrossCertPairSubsystem: didn't find a pair!");
                    addCAcert(conn, cert.getEncoded());
                    logger.debug("CrossCertPairSubsystem: potential cross ca cert added to crossCerts entry successfully");
                }

            } else {
                logger.info("CrossCertPairSubsystem: ldap search found no " + DN_XCERTS);
            }

        } catch (IOException e) {
            throw new EBaseException("CrossCertPairSubsystem: importCert() failed:" + e.toString(), e);

        } catch (LDAPException e) {
            logger.error("CrossCertPairSubsystem: " + e.getMessage(), e);
            throw new EBaseException("CrossCertPairSubsystem: importCert() failed:" + e.toString(), e);

        } catch (ELdapException e) {
            logger.error("CrossCertPairSubsystem: " + e.getMessage(), e);
            throw new EBaseException("CrossCertPairSubsystem: importCert() failed:" + e.toString(), e);

        } catch (CertificateException e) {
            logger.error("CrossCertPairSubsystem: " + e.getMessage(), e);
            throw new EBaseException("CrossCertPairSubsystem: importCert() failed:" + e.toString(), e);

        } finally {
            try {
                returnConn(conn);
            } catch (ELdapException e) {
                logger.error("CrossCertPairSubsystem: " + e.getMessage(), e);
                throw new EBaseException("CrossCertPairSubsystem: importCert() failed:" + e.toString());
            }
        }
        logger.debug("CrossCertPairSubsystem: importCert(Object) completed");
    }

    /**
     * are cert1 and cert2 cross-signed certs?
     *
     * @param cert1 the cert for comparison in our internal db
     * @param cert2 the cert that's being considered
     */
    protected boolean arePair(X509Certificate cert1, X509Certificate cert2) {
        // 1. does cert1's issuer match cert2's subject?
        // 2. does cert2's issuer match cert1's subject?
        if (cert1.getIssuerDN().equals(cert2.getSubjectDN())
                && cert2.getIssuerDN().equals(cert1.getSubjectDN()))
            return true;
        else
            return false;
    }

    public X509Certificate byteArray2X509Cert(byte[] certBytes)
            throws CertificateException {
        logger.debug("CrossCertPairSubsystem: in bytearray2X509Cert()");
        ByteArrayInputStream inStream = new
                ByteArrayInputStream(certBytes);

        CertificateFactory cf =
                CertificateFactory.getInstance("X.509");

        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

        logger.debug("CrossCertPairSubsystem: done bytearray2X509Cert()");
        return cert;
    }

    public synchronized void addXCertPair(LDAPConnection conn,
            LDAPAttribute certPairs, CertificatePair pair)
            throws LDAPException, IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        pair.encode(bos);

        if (ByteValueExists(certPairs, bos.toByteArray()) == true) {
            logger.debug("CrossCertPairSubsystem: cross cert pair exists in internal db, don't add again");
            return;
        }

        // add certificatePair
        LDAPModificationSet modSet = new LDAPModificationSet();

        modSet.add(LDAPModification.ADD,
                new LDAPAttribute(LDAP_ATTR_XCERT_PAIR, bos.toByteArray()));
        conn.modify(DN_XCERTS + "," + mBaseDN, modSet);
    }

    /**
     * checks if a byte attribute has a certain value.
     */
    public static boolean ByteValueExists(LDAPAttribute attr, byte[] bval) {
        if (attr == null) {
            return false;
        }
        @SuppressWarnings("unchecked")
        Enumeration<byte[]> vals = attr.getByteValues();
        byte[] val = null;

        while (vals.hasMoreElements()) {
            val = vals.nextElement();
            if (val.length == 0)
                continue;
            if (byteArraysAreEqual(val, bval)) {
                return true;
            }
        }
        return false;
    }

    /**
     * compares contents two byte arrays returning true if exactly same.
     */
    static public boolean byteArraysAreEqual(byte[] a, byte[] b) {
        logger.debug("CrossCertPairSubsystem: in byteArraysAreEqual()");
        if (a.length != b.length) {
            logger.debug("CrossCertPairSubsystem: exiting byteArraysAreEqual(): false");
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                logger.debug("CrossCertPairSubsystem: exiting byteArraysAreEqual(): false");
                return false;
            }
        }
        logger.debug("CrossCertPairSubsystem: exiting byteArraysAreEqual(): true");
        return true;
    }

    public synchronized void addCAcert(LDAPConnection conn, byte[] certEnc)
            throws LDAPException {
        LDAPModificationSet modSet = new
                LDAPModificationSet();

        modSet.add(LDAPModification.ADD,
                new LDAPAttribute(LDAP_ATTR_CA_CERT, certEnc));
        conn.modify(DN_XCERTS + "," + mBaseDN, modSet);
    }

    public synchronized void deleteCAcert(LDAPConnection conn, byte[] certEnc)
            throws LDAPException {
        LDAPModificationSet modSet = new
                LDAPModificationSet();

        modSet.add(LDAPModification.DELETE,
                new LDAPAttribute(LDAP_ATTR_CA_CERT, certEnc));
        conn.modify(DN_XCERTS + "," + mBaseDN, modSet);
    }

    /**
     * publish all cert pairs, if publisher is on
     */
    public synchronized void publishCertPairs() throws EBaseException {
        LDAPConnection conn = null;

        if ((mPublisherProcessor == null) ||
                !mPublisherProcessor.isCertPublishingEnabled())
            return;

        try {
            conn = getConn();
            // search in internal db for xcerts
            LDAPSearchResults res = conn.search(mBaseDN, LDAPv2.SCOPE_SUB,
                    DN_XCERTS, null, false);

            logger.debug("CrossCertPairSubsystem: trying to publish cert pairs, if any");
            if ((res == null) || (res.hasMoreElements() == false)) {
                logger.debug("CrossCertPairSubsystem: no cross cert pairs to publish");
                return;
            }

            if (res.hasMoreElements()) {
                logger.info("CrossCertPairSubsystem: ldap search found " + DN_XCERTS);

                LDAPEntry entry = (LDAPEntry) res.nextElement();
                LDAPAttribute xcerts = entry.getAttribute(LDAP_ATTR_XCERT_PAIR);

                if (xcerts == null) {
                    logger.debug("CrossCertPairSubsystem: no cross cert pairs to publish");
                    return;
                }

                @SuppressWarnings("unchecked")
                Enumeration<byte[]> en = xcerts.getByteValues();

                if ((en == null) || (en.hasMoreElements() == false)) {
                    logger.debug("CrossCertPairSubsystem: publishCertPair found no pairs in internal db");
                    return;
                }
                byte[] val = null;

                while (en.hasMoreElements()) {
                    val = en.nextElement();
                    logger.debug("CrossCertPairSubsystem: val =" + val.length);
                    if (val.length == 0) {
                        continue;
                    } else {
                        try {
                            //found a cross cert pair, publish if we could
                            IXcertPublisherProcessor xp = null;

                            xp = (IXcertPublisherProcessor) mPublisherProcessor;
                            xp.publishXCertPair(val);
                        } catch (Exception e) {
                            throw new EBaseException("CrossCertPairSubsystem: publishCertPairs() failed:"
                                    + e.toString());
                        }
                    }
                }// while
            }//if
        } catch (Exception e) {
            throw new EBaseException("CrossCertPairSubsystem: publishCertPairs() failed:" + e.toString());
        }
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

        throw new ELdapException("Ldap Connection Factory is null");
    }

    protected void returnConn(LDAPConnection conn) throws ELdapException {
        if (mLdapConnFactory != null)
            mLdapConnFactory.returnConn(conn);
    }

    public void startup() throws EBaseException {
    }

    /**
     * Stops this system.
     */
    public synchronized void shutdown() {
        if (mLdapConnFactory != null) {
            try {
                mLdapConnFactory.reset();
            } catch (ELdapException e) {
                logger.warn("CrossCertPairSubsystem shutdown exception: " + e.getMessage(), e);
            }
        }
    }

    /*
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }
}
