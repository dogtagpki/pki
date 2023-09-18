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
package com.netscape.cmscore.ldap;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.publish.Mapper;
import com.netscape.certsrv.publish.Publisher;
import com.netscape.cms.publish.mappers.LdapCertSubjMap;
import com.netscape.cms.publish.publishers.FileBasedPublisher;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestNotifier;

import netscape.ldap.LDAPConnection;

/**
 * Controls the publishing process from the top level. Maintains
 * a collection of Publishers , Mappers, and Publish Rules.
 */
public class CAPublisherProcessor extends PublisherProcessor {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAPublisherProcessor.class);

    public final static String PROP_LOCAL_CA = "cacert";
    public final static String PROP_LOCAL_CRL = "crl";
    public final static String PROP_CERTS = "certs";
    public final static String PROP_XCERT = "xcert";

    protected CertificateAuthority ca;
    private boolean createOwnDNEntry;

    public CAPublisherProcessor(String id) {
        super(id);
    }

    public CertificateAuthority getAuthority() {
        return ca;
    }

    public void init(CertificateAuthority ca, PublishingConfig config) throws EBaseException {

        this.ca = ca;
        this.createOwnDNEntry = config.getBoolean("createOwnDNEntry", false);

        super.init(config);
    }

    @Override
    public void startup() throws EBaseException {

        super.startup();

        CAEngine engine = CAEngine.getInstance();

        if (mConfig.isEnabled()) {

            if (requestListener != null) {
                engine.registerRequestListener(requestListener);
            }

            PublishingQueueConfig queueConfig = mConfig.getQueueConfig();

            if (queueConfig != null) {

                logger.info("CAPublisherProcessor: Publishing queue:");

                boolean isPublishingQueueEnabled = queueConfig.isEnabled();
                logger.info("CAPublisherProcessor: - enabled: " + isPublishingQueueEnabled);

                int publishingQueuePriorityLevel = queueConfig.getPriorityLevel();
                logger.info("CAPublisherProcessor: - priority level: " + publishingQueuePriorityLevel);

                int maxNumberOfPublishingThreads = queueConfig.getMaxNumberOfThreads();
                logger.info("CAPublisherProcessor: - max threads: " + maxNumberOfPublishingThreads);

                int publishingQueuePageSize = queueConfig.getPageSize();
                logger.info("CAPublisherProcessor: - page size: " + publishingQueuePageSize);

                int savePublishingStatus = queueConfig.getSaveStatus();
                logger.info("CAPublisherProcessor: - save status: " + savePublishingStatus);

                RequestNotifier requestNotifier = engine.getRequestNotifier();
                requestNotifier.setPublishingQueue(
                        isPublishingQueueEnabled,
                        publishingQueuePriorityLevel,
                        maxNumberOfPublishingThreads,
                        publishingQueuePageSize,
                        savePublishingStatus);
            }
        }
    }

    @Override
    public void shutdown() {

        logger.debug("Shuting down CA publishing");

        if (requestListener != null) {
            CAEngine engine = CAEngine.getInstance();
            // requestListener.shutdown();
            engine.removeRequestListener(requestListener);
        }

        super.shutdown();
    }

    /**
     * Set published flag - true when published, false when unpublished.
     * Not exist means not published.
     *
     * @param serialNo serial number of publishable object.
     * @param published true for published, false for not.
     */
    public void setPublishedFlag(BigInteger serialNo, boolean published) {

        try {
            CAEngine engine = CAEngine.getInstance();
            CertificateRepository certdb = engine.getCertificateRepository();
            CertRecord certRec = certdb.readCertificateRecord(serialNo);
            MetaInfo metaInfo = certRec.getMetaInfo();

            if (metaInfo == null) {
                metaInfo = new MetaInfo();
            }

            metaInfo.set(CertRecord.META_LDAPPUBLISH, String.valueOf(published));
            ModificationSet modSet = new ModificationSet();

            modSet.add(CertRecord.ATTR_META_INFO, Modification.MOD_REPLACE, metaInfo);
            certdb.modifyCertificateRecord(serialNo, modSet);

        } catch (EBaseException e) {
            // not fatal. just log warning.
            logger.warn("CAPublisherProcessor: Cannot mark cert 0x" + serialNo.toString(16)
                    + " published as " + published + " in the ldap directory.");
            logger.warn("CAPublisherProcessor: Cert Record not found: " + e.getMessage(), e);
            logger.warn("CAPublisherProcessor: Don't be alarmed if it's a subordinate ca or clone's ca siging cert.");
            logger.warn("CAPublisherProcessor: Otherwise your internal db may be corrupted.");
        }
    }

    /**
     * Publish ca cert, UpdateDir.java, jobs, request listeners
     *
     * @param cert X509 certificate to be published.
     * @exception ELdapException publish failed due to Ldap error.
     * @throws ELdapException
     */
    public void publishCACert(X509Certificate cert) throws ELdapException {

        boolean error = false;
        StringBuffer errorRule = new StringBuffer();

        if (!isCertPublishingEnabled()) {
            return;
        }

        logger.debug("PublishProcessor::publishCACert");

        // get mapper and publisher for cert type.
        Enumeration<LdapRule> rules = getRules(PROP_LOCAL_CA);

        if (rules == null || !rules.hasMoreElements()) {
            if (ca.isClone()) {
                logger.warn("CAPublisherProcessor: No rule is found for publishing: " + PROP_LOCAL_CA + " in this clone.");
                return;
            }
            logger.warn(CMS.getLogMessage("CMSCORE_LDAP_NO_RULE_FOUND", PROP_LOCAL_CA));
            //throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_RULE_MATCHED", PROP_LOCAL_CA));
            return;
        }

        while (rules.hasMoreElements()) {
            LdapRule rule = rules.nextElement();

            if (rule == null) {
                logger.error("CAPublisherProcessor: Missing publishing rule");
                throw new ELdapException("Missing publishing rule");
            }

            logger.info("CAPublisherProcessor: publish certificate type=" + PROP_LOCAL_CA +
                    " rule=" + rule.getInstanceName() + " publisher=" +
                    rule.getPublisher());

            try {
                Mapper mapper = null;

                String mapperName = rule.getMapper();

                if (mapperName != null && !mapperName.trim().equals("")) {
                    mapper = getActiveMapperInstance(mapperName);
                }

                publishNow(mapper, getActivePublisherInstance(rule.getPublisher()), null/* NO REQUEsT */, cert);
                logger.info("CAPublisherProcessor: published certificate using rule " + rule.getInstanceName());

            } catch (Exception e) {
                // continue publishing even publisher has errors
                logger.warn("CAPublisherProcessor::publishCACert returned error: " + e.getMessage(), e);
                error = true;
                errorRule.append(" " + rule.getInstanceName() + " error:" + e);
            }
        }
        // set the ldap published flag.
        if (!error) {
            setPublishedFlag(cert.getSerialNumber(), true);
        } else {
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_FAILED", errorRule.toString()));
        }
    }

    /**
     * This function is never called. CMS does not unpublish
     * CA certificate.
     * @throws ELdapException
     */
    public void unpublishCACert(X509Certificate cert) throws ELdapException {

        boolean error = false;
        StringBuffer errorRule = new StringBuffer();

        if (!isCertPublishingEnabled()) {
            return;
        }

        // get mapper and publisher for cert type.
        Enumeration<LdapRule> rules = getRules(PROP_LOCAL_CA);

        if (rules == null || !rules.hasMoreElements()) {
            if (ca.isClone()) {
                logger.warn("CAPublisherProcessor: No rule is found for unpublishing: " + PROP_LOCAL_CA + " in this clone.");
                return;
            }
            logger.error("CAPublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_NO_UNPUBLISHING_RULE_FOUND", PROP_LOCAL_CA));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_RULE_MATCHED", PROP_LOCAL_CA));
        }

        while (rules.hasMoreElements()) {
            LdapRule rule = rules.nextElement();

            if (rule == null) {
                logger.error("CAPublisherProcessor::unpublishCACert() - "
                         + "rule is null!");
                throw new ELdapException("rule is null");
            }

            try {
                logger.info("CAPublisherProcessor: unpublish certificate type=" +
                        PROP_LOCAL_CA + " rule=" + rule.getInstanceName() +
                        " publisher=" + rule.getPublisher());

                Mapper mapper = null;

                String mapperName = rule.getMapper();

                if (mapperName != null && !mapperName.trim().equals("")) {
                    mapper = getActiveMapperInstance(mapperName);
                }

                unpublishNow(mapper, getActivePublisherInstance(rule.getPublisher()), null/* NO REQUEST */, cert);
                logger.warn("CAPublisherProcessor: unpublished certificate using rule " + rule.getInstanceName());

            } catch (Exception e) {
                // continue publishing even publisher has errors
                logger.warn("CAPublisherProcessor: " + e.getMessage(), e);
                error = true;
                errorRule.append(" " + rule.getInstanceName());
            }
        }

        // set the ldap published flag.
        if (!error) {
            setPublishedFlag(cert.getSerialNumber(), false);
        } else {
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_UNPUBLISH_FAILED", errorRule.toString()));
        }
    }

    /**
     * Publish crossCertificatePair
     *
     * @param pair Byte array representing cert pair.
     * @throws ELdapException
     * @exception EldapException publish failed due to Ldap error.
     */
    public void publishXCertPair(byte[] pair) throws ELdapException {

        String errorRule = "";

        if (!isCertPublishingEnabled()) {
            return;
        }

        logger.debug("CAPublisherProcessor: in publishXCertPair()");

        // get mapper and publisher for cert type.
        Enumeration<LdapRule> rules = getRules(PROP_XCERT);

        if (rules == null || !rules.hasMoreElements()) {
            if (ca.isClone()) {
                logger.warn("CAPublisherProcessor: No rule is found for publishing: " + PROP_LOCAL_CA + " in this clone.");
                return;
            }
            logger.error("CAPublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_NO_RULE_FOUND", PROP_XCERT));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_RULE_MATCHED", PROP_XCERT));
        }

        while (rules.hasMoreElements()) {
            LdapRule rule = rules.nextElement();

            if (rule == null) {
                logger.error("CAPublisherProcessor: Missing publishing rule");
                throw new ELdapException("Missing publishing rule");
            }

            logger.info("CAPublisherProcessor: publish certificate type=" + PROP_XCERT +
                    " rule=" + rule.getInstanceName() + " publisher=" +
                    rule.getPublisher());
            try {
                Mapper mapper = null;

                String mapperName = rule.getMapper();

                if (mapperName != null && !mapperName.trim().equals("")) {
                    mapper = getActiveMapperInstance(mapperName);
                }

                publishNow(mapper, getActivePublisherInstance(rule.getPublisher()), null/* NO REQUEsT */, pair);
                logger.info("CAPublisherProcessor: published Xcertificates using rule " + rule.getInstanceName());

            } catch (Exception e) {
                // continue publishing even publisher has errors
                logger.warn("CAPublisherProcessor: " + e.getMessage(), e);
                errorRule = errorRule + " " + rule.getInstanceName() +
                        " error:" + e;

                logger.warn("CAPublisherProcessor::publishXCertPair: error: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Publishs regular user certificate based on the criteria
     * set in the request.
     *
     * @param cert X509 certificate to be published.
     * @param req request which provides the criteria
     * @exception ELdapException publish failed due to Ldap error.
     * @throws ELdapException
     */
    public void publishCert(X509Certificate cert, Request req) throws ELdapException {

        CertId certID = new CertId(cert.getSerialNumber());
        logger.info("CAPublisherProcessor: Publishing cert " + certID.toHexString());

        if (!isCertPublishingEnabled()) {
            logger.info("CAPublisherProcessor: Cert publishing disabled");
            return;
        }

        boolean error = false;
        StringBuffer errorRule = new StringBuffer();

        // get mapper and publisher for cert type.
        Enumeration<LdapRule> rules = getRules("certs", req);

        // Bugscape  #52306  -  Remove superfluous log messages on failure
        if (rules == null || !rules.hasMoreElements()) {
            logger.info("CAPublisherProcessor: No rules enabled");

            error = true;
            errorRule.append("No rules enabled");
        }

        while (rules != null && rules.hasMoreElements()) {
            LdapRule rule = rules.nextElement();
            logger.info("CAPublisherProcessor: Publishing cert with rule " + rule.getInstanceName());

            try {
                String publisherName = rule.getPublisher();
                logger.info("CAPublisherProcessor: - publisher: " + publisherName);
                Publisher p = getActivePublisherInstance(publisherName);

                String mapperName = rule.getMapper();
                logger.info("CAPublisherProcessor: - mapper: " + mapperName);

                Mapper m = null;
                if (mapperName != null) {
                    m = getActiveMapperInstance(mapperName);
                }

                publishNow(m, p, req, cert);

                logger.info("CAPublisherProcessor: Published cert using rule " + rule.getInstanceName());

            } catch (Exception e) {
                // continue publishing even publisher has errors
                logger.warn("CAPublisherProcessor: " + e.getMessage(), e);
                error = true;
                errorRule.append(" " + rule.getInstanceName());
            }
        }
        // set the ldap published flag.
        if (!error) {
            setPublishedFlag(cert.getSerialNumber(), true);
        } else {
            logger.error("PublishProcessor::publishCert : " + CMS.getUserMessage("CMS_LDAP_PUBLISH_FAILED", errorRule.toString()));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_FAILED", errorRule.toString()));
        }
    }

    /**
     * Unpublish user certificate. This is used by
     * UnpublishExpiredJob.
     *
     * @param cert X509 certificate to be unpublished.
     * @param req request which provides the criteria
     * @exception ELdapException unpublish failed due to Ldap error.
     * @throws ELdapException
     */
    public void unpublishCert(X509Certificate cert, Request req) throws ELdapException {

        CertId certID = new CertId(cert.getSerialNumber());
        logger.info("CAPublisherProcessor: Unpublishing cert " + certID.toHexString());

        if (!isCertPublishingEnabled()) {
            logger.info("CAPublisherProcessor: Cert publishing disabled");
            return;
        }

        boolean error = false;
        StringBuffer errorRule = new StringBuffer();

        // get mapper and publisher for cert type.
        Enumeration<LdapRule> rules = getRules("certs", req);

        if (rules == null || !rules.hasMoreElements()) {
            logger.error("CAPublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_NO_UNPUBLISHING_RULE_FOUND_FOR_REQUEST", "certs", req.getRequestId().toHexString()));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_RULE_MATCHED", req.getRequestId().toString()));
        }

        while (rules.hasMoreElements()) {
            LdapRule rule = rules.nextElement();

            if (rule == null) {
                logger.error("CAPublisherProcessor: Missing publishing rule");
                throw new ELdapException("Missing publishing rule");
            }

            try {
                logger.info("CAPublisherProcessor: Unpublishing cert (with request) type=certs rule=" + rule.getInstanceName() + " publisher=" + rule.getPublisher());

                Mapper mapper = null;
                String mapperName = rule.getMapper();

                if (mapperName != null && !mapperName.trim().equals("")) {
                    mapper = getActiveMapperInstance(mapperName);
                }

                unpublishNow(mapper, getActivePublisherInstance(rule.getPublisher()), req, cert);

                logger.info("CAPublisherProcessor: Unpublished cert using rule " + rule.getInstanceName());

            } catch (Exception e) {
                // continue publishing even publisher has errors
                logger.warn("CAPublisherProcessor: " + e.getMessage(), e);
                error = true;
                errorRule.append(" " + rule.getInstanceName());
            }
        }

        // set the ldap published flag.
        if (!error) {
            setPublishedFlag(cert.getSerialNumber(), false);
        } else {
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_UNPUBLISH_FAILED", errorRule.toString()));
        }
    }

    /**
     * publishes a CRL by mapping the issuer name in the CRL to an entry
     * and publishing it there. entry must be a certificate authority.
     * Note that this is used by cmsgateway/cert/UpdateDir.java
     *
     * @param crl Certificate Revocation List
     * @param crlIssuingPointId name of the issuing point.
     * @exception ELdapException publish failed due to Ldap error.
     * @throws ELdapException
     */
    public void publishCRL(X509CRLImpl crl, String crlIssuingPointId) throws ELdapException {

        if (!isCRLPublishingEnabled()) {
            return;
        }

        logger.info("CAPublisherProcessor: Publishing CRL " + crl.getCRLNumber() + " to " + crlIssuingPointId);

        boolean error = false;
        String errorRule = "";

        // get mapper and publisher for cert type.
        Enumeration<LdapRule> rules = getRules(PROP_LOCAL_CRL);

        if (rules == null || !rules.hasMoreElements()) {
            logger.error("CAPublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_NO_RULE_FOR_CRL"));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_RULE_MATCHED", PROP_LOCAL_CRL));
        }

        LDAPConnection conn = null;
        String dn = null;

        try {
            if (mLdapConnModule != null) {
                conn = mLdapConnModule.getConn();
            }

            logger.info("CAPublisherProcessor: Publishing rules:");
            while (rules.hasMoreElements()) {

                LdapRule rule = rules.nextElement();
                logger.info("CAPublisherProcessor: - rule: " + rule.getInstanceName());

                Mapper mapper = null;
                dn = null;

                try {
                    String mapperName = rule.getMapper();
                    logger.info("CAPublisherProcessor:   mapper: " + mapperName);

                    if (mapperName != null && !mapperName.trim().equals("")) {
                        mapper = getActiveMapperInstance(mapperName);
                    }

                    if (mapper == null || mapper.getImplName().equals("NoMap")) {
                        dn = ((X500Name) crl.getIssuerDN()).toLdapDNString();

                    } else {
                        dn = mapper.map(conn, crl);
                        if (!createOwnDNEntry) {
                            if (dn == null) {
                                logger.error("CAPublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_MAPPER_NOT_MAP", rule.getMapper()));
                                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH", crl.getIssuerDN().toString()));
                            }
                        }
                    }

                    logger.info("CAPublisherProcessor: Publishing to " + dn);

                    String publisherName = rule.getPublisher();
                    logger.info("CAPublisherProcessor: - publisher: " + publisherName);

                    Publisher publisher = getActivePublisherInstance(publisherName);

                    if (publisher != null) {

                        if (publisher instanceof FileBasedPublisher) {
                            ((FileBasedPublisher) publisher).setIssuingPointId(crlIssuingPointId);
                        }

                        publisher.publish(conn, dn, crl);
                        logger.info("CAPublisherProcessor: Published CRL");
                    }

                    // continue publishing even publisher has errors

                } catch (Exception e) {
                    logger.warn("Unable to publish CRL to " + dn + ": " + e.getMessage(), e);
                    error = true;
                    errorRule = errorRule + " " + rule.getInstanceName();
                }
            }

        } catch (ELdapException e) {
            logger.error("Error publishing CRL to " + dn + ": " + e.getMessage(), e);
            throw e;

        } finally {
            if (conn != null) {
                mLdapConnModule.returnConn(conn);
            }
        }

        if (error) {
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_FAILED", errorRule));
        }
    }

    /**
     * publishes a crl by mapping the issuer name in the crl to an entry
     * and publishing it there. entry must be a certificate authority.
     *
     * @param dn Distinguished name to publish.
     * @param crl Certificate Revocation List
     * @exception ELdapException publish failed due to Ldap error.
     * @throws ELdapException
     */
    public void publishCRL(String dn, X509CRL crl) throws ELdapException {

        boolean error = false;
        String errorRule = "";

        if (!isCRLPublishingEnabled()) {
            return;
        }

        // get mapper and publisher for cert type.
        Enumeration<LdapRule> rules = getRules(PROP_LOCAL_CRL);

        if (rules == null || !rules.hasMoreElements()) {
            logger.error("CAPublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_NO_RULE_FOR_CRL"));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_RULE_MATCHED",
                    PROP_LOCAL_CRL));
        }

        LDAPConnection conn = null;
        Publisher publisher = null;

        try {
            if (mLdapConnModule != null) {
                conn = mLdapConnModule.getConn();
            }

            while (rules.hasMoreElements()) {
                LdapRule rule = rules.nextElement();

                logger.info("CAPublisherProcessor: publish crl dn=" + dn + " rule=" +
                        rule.getInstanceName() + " publisher=" +
                        rule.getPublisher());
                try {
                    publisher = getActivePublisherInstance(rule.getPublisher());
                    if (publisher != null) {
                        publisher.publish(conn, dn, crl);
                        logger.info("CAPublisherProcessor: published crl using rule=" + rule.getInstanceName());
                    }

                } catch (Exception e) {
                    logger.warn("Error publishing CRL to " + dn + ": " + e.getMessage(), e);
                    error = true;
                    errorRule = errorRule + " " + rule.getInstanceName();
                }
            }

        } catch (ELdapException e) {
            logger.error("Error publishing CRL to " + dn + ": " + e.getMessage(), e);
            throw e;

        } finally {
            if (conn != null) {
                mLdapConnModule.returnConn(conn);
            }
        }

        if (error) {
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_PUBLISH_FAILED", errorRule));
        }
    }

    private void publishNow(Mapper mapper, Publisher publisher, Request r, Object obj) throws ELdapException {

        if (!isCertPublishingEnabled()) {
            return;
        }

        logger.info("CAPublisherProcessor: Running publisher " + publisher.getImplName());

        LDAPConnection conn = null;
        try {
            Object dirdn = null;

            if (mapper != null) {
                logger.info("CAPublisherProcessor: LDAP connection module: " + mLdapConnModule);
                if (mLdapConnModule != null) {
                    try {
                        conn = mLdapConnModule.getConn();
                    } catch (ELdapException e) {
                        throw e;
                    }
                }

                try {
                    if ((mapper instanceof LdapCertSubjMap) && ((LdapCertSubjMap) mapper).useAllEntries()) {
                        dirdn = ((LdapCertSubjMap) mapper).mapAll(conn, r, obj);
                    } else {
                        dirdn = mapper.map(conn, r, obj);
                    }

                } catch (Throwable e1) {
                    logger.error("CAPublisherProcessor: " + e1.getMessage(), e1);
                    throw e1;
                }
            }

            X509Certificate cert = (X509Certificate) obj;

            try {
                if (dirdn instanceof Vector) {

                    @SuppressWarnings("unchecked")
                    Vector<String> dirdnVector = (Vector<String>) dirdn;
                    logger.info("CAPublisherProcessor: Dir DN:");

                    int n = dirdnVector.size();
                    for (int i = 0; i < n; i++) {
                        String dn = dirdnVector.elementAt(i);
                        logger.info("CAPublisherProcessor: Publishing to " + dn);
                        publisher.publish(conn, dn, cert);
                    }

                } else if (dirdn instanceof String || publisher instanceof com.netscape.cms.publish.publishers.FileBasedPublisher) {
                    logger.info("CAPublisherProcessor: Publishing to " + dirdn);
                    publisher.publish(conn, (String) dirdn, cert);
                }

            } catch (Throwable e1) {
                logger.error("CAPublisherProcessor: " + e1.getMessage(), e1);
                throw e1;
            }

            logger.info("CAPublisherProcessor: Published cert 0x" + cert.getSerialNumber().toString(16));

        } catch (ELdapException e) {
            throw e;

        } catch (Throwable e) {
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH", e.toString()));

        } finally {
            if (conn != null) {
                mLdapConnModule.returnConn(conn);
            }
        }
    }

    // for crosscerts
    private void publishNow(Mapper mapper, Publisher publisher, Request r, byte[] bytes) throws EBaseException {

        if (!isCertPublishingEnabled()) {
            return;
        }

        logger.info("CAPublisherProcessor: in publishNow() for xcerts");

        // use ca cert publishing map and rule
        X509Certificate caCert = ca.getCACert();

        LDAPConnection conn = null;

        try {
            String dirdn = null;

            if (mapper != null) {
                if (mLdapConnModule != null) {
                    conn = mLdapConnModule.getConn();
                }
                try {
                    dirdn = mapper.map(conn, r, caCert);
                    logger.debug("CAPublisherProcessor: dirdn=" + dirdn);

                } catch (Throwable e1) {
                    logger.error("Error mapping: mapper=" + mapper + " error=" + e1.getMessage(), e1);
                    throw e1;
                }
            }

            try {
                logger.debug("CAPublisherProcessor: publisher impl name=" + publisher.getImplName());
                publisher.publish(conn, dirdn, bytes);

            } catch (Throwable e1) {
                logger.error("Error publishing: publisher=" + publisher + " error=" + e1.getMessage(), e1);
                throw e1;
            }

            logger.info("CAPublisherProcessor: published crossCertPair");

        } catch (ELdapException e) {
            throw e;

        } catch (Throwable e) {
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH", e.toString()));

        } finally {
            if (conn != null) {
                mLdapConnModule.returnConn(conn);
            }
        }
    }

    private void unpublishNow(Mapper mapper, Publisher publisher, Request r, Object obj) throws ELdapException {

        if (!isCertPublishingEnabled()) {
            return;
        }

        X509Certificate cert = (X509Certificate) obj;
        logger.info("CAPublisherProcessor: Unpublishing cert 0x" + cert.getSerialNumber().toString(16));

        LDAPConnection conn = null;

        try {
            String dirdn = null;

            if (mapper != null) {
                if (mLdapConnModule != null) {
                    conn = mLdapConnModule.getConn();
                }
                dirdn = mapper.map(conn, r, obj);
            }

            publisher.unpublish(conn, dirdn, cert);

            logger.info("CAPublisherProcessor: Unpublished cert 0x" + cert.getSerialNumber().toString(16));

        } catch (ELdapException e) {
            throw e;

        } finally {
            if (conn != null) {
                mLdapConnModule.returnConn(conn);
            }
        }
    }

    /**
     * Return true if Certificate Publishing is enabled.
     * @return true if enabled, false otherwise
     */
    public boolean isCertPublishingEnabled() {

        if (!mInited) return false;

        try {
            if (!mConfig.isEnabled()) return false;
            return mConfig.isCertEnabled();

        } catch (EBaseException e) {
            // this should never happen
            logger.error("Error getting publishing config: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Return true if CRL publishing is enabled,
     * @return true if enabled,  false otherwise.
     */
    public boolean isCRLPublishingEnabled() {

        if (!mInited) return false;

        try {
            if (!mConfig.isEnabled()) return false;
            return mConfig.isCRLEnabled();

        } catch (EBaseException e) {
            // this should never happen
            logger.error("Error getting publishing config: " + e.getMessage(), e);
            return false;
        }
    }
}
