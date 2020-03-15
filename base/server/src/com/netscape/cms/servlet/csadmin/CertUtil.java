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
package com.netscape.cms.servlet.csadmin;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;

import javax.ws.rs.core.MultivaluedMap;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkcs11.PK11Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.xml.XMLObject;

public class CertUtil {

    public final static Logger logger = LoggerFactory.getLogger(CertUtil.class);

    static final int LINE_COUNT = 76;

    public static X509CertImpl createRemoteCert(String hostname,
            int port, MultivaluedMap<String, String> content)
            throws Exception {

        logger.debug("CertUtil: content: " + content);

        String c = Configurator.post(hostname, port, true, "/ca/ee/ca/profileSubmit", content, null, null);

        if (c != null) {
            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject parser;
            try {
                parser = new XMLObject(bis);
            } catch (SAXException e) {
                logger.error("Response: " + c);
                logger.error("CertUtil: Unable to parse XML response: " + e, e);
                throw e;
            }

            String status = parser.getValue("Status");

            logger.debug("CertUtil: status: " + status);
            if (!status.equals("0")) {
                String error = parser.getValue("Error");
                logger.error("CertUtil: error: " + error);
                throw new IOException(error);
            }

            String b64 = parser.getValue("b64");

            logger.debug("CertUtil: cert: " + b64);
            b64 = CryptoUtil.normalizeCertAndReq(b64);
            byte[] b = CryptoUtil.base64Decode(b64);

            return new X509CertImpl(b);

        } else {
            logger.error("CertUtil: Missing CA response");
            throw new Exception("Missing CA response");
        }
    }

    // Dynamically inject the SubjectAlternativeName extension to a
    // local/self-signed master CA's request for its SSL Server Certificate.
    //
    // Since this information may vary from instance to
    // instance, obtain the necessary information from the
    // 'service.sslserver.san' value(s) in the instance's
    // CS.cfg, process these values converting each item into
    // its individual SubjectAlternativeName components, and
    // inject these values into the local request.
    //
    public static void injectSANextensionIntoRequest(IConfigStore config,
                           IRequest req) throws Exception {
        logger.debug("CertUtil: injectSANextensionIntoRequest() - injecting SAN " +
                  "entries into request . . .");
        int i = 0;
        if (config == null || req == null) {
            throw new EBaseException("injectSANextensionIntoRequest: parameters config and req cannot be null");
        }
        String sanHostnames = config.getString("service.sslserver.san");
        String sans[] = StringUtils.split(sanHostnames, ",");
        for (String san : sans) {
            logger.debug("CertUtil: injectSANextensionIntoRequest() injecting " +
                      "SAN hostname: " + san);
            req.setExtData("req_san_pattern_" + i, san);
            i++;
        }
        logger.debug("CertUtil: injectSANextensionIntoRequest() " + "injected " +
                  i + " SAN entries into request.");
    }

    // Dynamically apply the SubjectAlternativeName extension to a
    // remote PKI instance's request for its SSL Server Certificate.
    //
    // Since this information may vary from instance to
    // instance, obtain the necessary information from the
    // 'service.sslserver.san' value(s) in the instance's
    // CS.cfg, process these values converting each item into
    // its individual SubjectAlternativeName components, and
    // build an SSL Server Certificate URL extension consisting
    // of this information.
    //
    // 03/27/2013 - Should consider removing this
    //              "buildSANSSLserverURLExtension()"
    //              method if it becomes possible to
    //              embed a certificate extension into
    //              a PKCS #10 certificate request.
    //
    public static void buildSANSSLserverURLExtension(IConfigStore config, MultivaluedMap<String, String> content)
           throws Exception {

        logger.debug("CertUtil: buildSANSSLserverURLExtension() " +
                  "building SAN SSL Server Certificate URL extension . . .");

        if (config == null) {
            throw new EBaseException("injectSANextensionIntoRequest: parameter config cannot be null");
        }

        String sanHostnames = config.getString("service.sslserver.san");
        String sans[] = StringUtils.split(sanHostnames, ",");

        int i = 0;
        for (String san : sans) {
            logger.debug("CertUtil: buildSANSSLserverURLExtension() processing " +
                      "SAN hostname: " + san);
            // Add the DNSName for all SANs
            content.putSingle("req_san_pattern_" + i, san);
            i++;
        }

        content.putSingle("req_san_entries", "" + i);

        logger.debug("CertUtil: buildSANSSLserverURLExtension() " + "placed " +
                  i + " SAN entries into SSL Server Certificate URL.");
    }


    /*
     * create requests so renewal can work on these initial certs
     */
    public static IRequest createLocalRequest(
            IConfigStore cs,
            IRequestQueue queue,
            String tag,
            CertInfoProfile profile,
            X509CertInfo info,
            X509Key x509key)
            throws Exception {

        //        RequestId rid = new RequestId(serialNum);
        // just need a request, no need to get into a queue
        //        IRequest r = new EnrollmentRequest(rid);

        logger.debug("CertUtil: createLocalRequest(" + tag + ")");

        IRequest req = queue.newRequest("enrollment");

        req.setExtData("profile", "true");
        req.setExtData("requestversion", "1.0.0");
        req.setExtData("req_seq_num", "0");

        req.setExtData(EnrollProfile.REQUEST_CERTINFO, info);
        req.setExtData(EnrollProfile.REQUEST_EXTENSIONS, new CertificateExtensions());

        req.setExtData("requesttype", "enrollment");
        req.setExtData("requestor_name", "");
        req.setExtData("requestor_email", "");
        req.setExtData("requestor_phone", "");
        req.setExtData("profileRemoteHost", "");
        req.setExtData("profileRemoteAddr", "");
        req.setExtData("requestnotes", "");
        req.setExtData("isencryptioncert", "false");
        req.setExtData("profileapprovedby", "system");

        Boolean injectSAN = cs.getBoolean("service.injectSAN", false);
        logger.debug("createLocalCert: inject SAN: " + injectSAN);

        if (tag.equals("sslserver") && injectSAN) {
            injectSANextensionIntoRequest(cs, req);
        }

        req.setExtData("req_key", x509key.toString());

        String origProfileID = profile.getID();
        int idx = origProfileID.lastIndexOf('.');
        if (idx > 0) {
            origProfileID = origProfileID.substring(0, idx);
        }

        // store original profile id in cert request
        req.setExtData("origprofileid", origProfileID);

        // store mapped profile ID for use in renewal
        req.setExtData("profileid", profile.getProfileIDMapping());
        req.setExtData("profilesetid", profile.getProfileSetIDMapping());

        if (!tag.equals("signing")) {
            /*
             * (applies to non-CA-signing cert only)
             * installAdjustValidity tells ValidityDefault to adjust the
             * notAfter value to that of the CA's signing cert if needed
             */
            req.setExtData("installAdjustValidity", "true");
        }

        // mark request as complete
        logger.debug("certUtil: calling setRequestStatus");
        req.setRequestStatus(RequestStatus.COMPLETE);

        return req;
    }

    /**
     * update local cert request with the actual request
     * called from CertRequestPanel.java
     * @throws EBaseException
     * @throws EPropertyNotFound
     */
    public static void updateLocalRequest(
            String reqId,
            byte[] certReq,
            String reqType,
            String subjectName
            ) throws Exception {

        logger.debug("CertUtil: updateLocalRequest(" + reqId + ")");

        CMSEngine engine = CMS.getCMSEngine();
        ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);
        IRequestQueue queue = ca.getRequestQueue();

        IRequest req = queue.findRequest(new RequestId(reqId));

        if (certReq != null) {
            logger.debug("CertUtil: updating cert request");
            String certReqs = CryptoUtil.base64Encode(certReq);
            String certReqf = CryptoUtil.reqFormat(certReqs);
            req.setExtData("cert_request", certReqf);
        }

        req.setExtData("cert_request_type", reqType);

        if (subjectName != null) {
            logger.debug("CertUtil: updating request subject: " + subjectName);
            req.setExtData("subject", subjectName);
            new X500Name(subjectName); // check for errors
        }

        queue.updateRequest(req);
    }

    /**
     * reads from the admin cert profile caAdminCert.profile and determines the algorithm as follows:
     *
     * 1.  First gets list of allowed algorithms from profile (constraint.params.signingAlgsAllowed)
     *     If entry does not exist, uses entry "ca.profiles.defaultSigningAlgsAllowed" from CS.cfg
     *     If that entry does not exist, uses basic default
     *
     * 2.  Gets default.params.signingAlg from profile.
     *     If entry does not exist or equals "-", selects first algorithm in allowed algorithm list
     *     that matches CA signing key type
     *     Otherwise returns entry if it matches signing CA key type.
     *
     * @throws EBaseException
     * @throws IOException
     * @throws FileNotFoundException
     */

    public static String getAdminProfileAlgorithm(
            String caSigningKeyType,
            String profileFilename,
            String defaultSigningAlgsAllowed) throws Exception {

        Properties props = new Properties();
        props.load(new FileInputStream(profileFilename));

        Set<String> keys = props.stringPropertyNames();
        Iterator<String> iter = keys.iterator();
        String defaultAlg = null;
        String[] algsAllowed = null;

        while (iter.hasNext()) {
            String key = iter.next();
            if (key.endsWith("default.params.signingAlg")) {
                defaultAlg = props.getProperty(key);
            }
            if (key.endsWith("constraint.params.signingAlgsAllowed")) {
                algsAllowed = StringUtils.split(props.getProperty(key), ",");
            }
        }

        if (algsAllowed == null) { //algsAllowed not defined in profile, use a global setting
            algsAllowed = StringUtils.split(defaultSigningAlgsAllowed, ",");
        }

        if (ArrayUtils.isEmpty(algsAllowed)) {
            throw new EBaseException("No allowed signing algorithms defined.");
        }

        if (StringUtils.isNotEmpty(defaultAlg) && !defaultAlg.equals("-")) {
            // check if the defined default algorithm is valid
            if (! isAlgorithmValid(caSigningKeyType, defaultAlg)) {
                throw new EBaseException("Administrator cert cannot be signed by specfied algorithm." +
                                         "Algorithm incompatible with signing key");
            }

            for (String alg : algsAllowed) {
                if (defaultAlg.trim().equals(alg.trim())) {
                    return defaultAlg;
                }
            }
            throw new EBaseException(
                    "Administrator Certificate cannot be signed by the specified algorithm " +
                    "as it is not one of the allowed signing algorithms.  Check the admin cert profile.");
        }

        // no algorithm specified.  Pick the first allowed algorithm.
        for (String alg : algsAllowed) {
            if (isAlgorithmValid(caSigningKeyType, alg)) return alg;
        }

        throw new EBaseException(
                "Admin certificate cannot be signed by any of the specified possible algorithms." +
                "Algorithm is incompatible with the CA signing key type" );
    }

    private static boolean isAlgorithmValid(String signingKeyType, String algorithm) {
       return ((signingKeyType.equals("rsa") && algorithm.contains("RSA")) ||
               (signingKeyType.equals("ecc") && algorithm.contains("EC"))  ||
               (signingKeyType.equals("dsa") && algorithm.contains("DSA")));
    }

    public static X509CertInfo createCertInfo(
            String dn,
            String issuerdn,
            String keyAlgorithm,
            X509Key x509key,
            String type) throws Exception {

        logger.info("CertUtil: Creating certificate info for " + dn);

        Date date = new Date();

        CMSEngine engine = CMS.getCMSEngine();
        ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);
        ICertificateRepository cr = ca.getCertificateRepository();
        BigInteger serialNo = cr.getNextSerialNumber();

        X509CertInfo info;

        if (type.equals("selfsign")) {

            logger.debug("CertUtil: Creating self-signed certificate");
            CertificateIssuerName issuerdnObj = new CertificateIssuerName(new X500Name(dn));
            info = CryptoUtil.createX509CertInfo(x509key, serialNo, issuerdnObj, dn, date, date, keyAlgorithm);

        } else {

            logger.debug("CertUtil: Creating CA-signed certificate");
            CertificateIssuerName issuerdnObj = ca.getIssuerObj();

            if (issuerdnObj == null) {

                logger.debug("CertUtil: Reusing CA's CertificateIssuerName to preserve the DN encoding");
                info = CryptoUtil.createX509CertInfo(x509key, serialNo, issuerdnObj, dn, date, date, keyAlgorithm);

            } else {

                logger.debug("CertUtil: Creating new CertificateIssuerName");
                issuerdnObj = new CertificateIssuerName(new X500Name(issuerdn));
                info = CryptoUtil.createX509CertInfo(x509key, serialNo, issuerdnObj, dn, date, date, keyAlgorithm);
            }
        }

        logger.info("CertUtil: Cert info:\n" + info);
        return info;
    }

    public static X509CertImpl createLocalCert(
            IRequest req,
            CertInfoProfile profile,
            X509CertInfo info,
            java.security.PrivateKey signingPrivateKey,
            String caSigningKeyAlgo) throws Exception {

        profile.populate(req, info);

        X509CertImpl cert = CryptoUtil.signCert(signingPrivateKey, info, caSigningKeyAlgo);

        createCertRecord(req, profile, cert);

        // update request with cert
        req.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, cert);

        return cert;
    }

    public static void createCertRecord(
            IRequest request,
            CertInfoProfile profile,
            X509Certificate cert) throws Exception {

        X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());
        createCertRecord(request, profile, certImpl);
    }

    public static void createCertRecord(
            IRequest request,
            CertInfoProfile profile,
            X509CertImpl cert) throws Exception {

        logger.debug("CertUtil: createCertRecord(" +
                cert.getSerialNumber() + ", " +
                cert.getSubjectDN() + ")");

        CMSEngine engine = CMS.getCMSEngine();
        ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);
        ICertificateRepository cr = ca.getCertificateRepository();

        MetaInfo meta = new MetaInfo();
        meta.set(ICertRecord.META_REQUEST_ID, request.getRequestId().toString());
        meta.set(ICertRecord.META_PROFILE_ID, profile.getProfileIDMapping());

        ICertRecord record = cr.createCertRecord(cert.getSerialNumber(), cert, meta);
        cr.addCertificateRecord(record);
    }

    public static void addUserCertificate(X509CertImpl cert) {
        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();
        PreOpConfig preopConfig = cs.getPreOpConfig();
        int num = 0;
        try {
            num = preopConfig.getInteger("subsystem.count", 0);
        } catch (Exception e) {
            logger.warn("Unable to retrieve server configuration: " + e, e);
        }

        UGSubsystem system = engine.getUGSubsystem();
        String id = "user" + num;

        try {
            String sysType = cs.getType();
            String machineName = cs.getHostname();
            String securePort = cs.getString("service.securePort", "");
            id = sysType + "-" + machineName + "-" + securePort;
        } catch (Exception e) {
            logger.warn("Unable to retrieve server configuration: " + e, e);
        }

        num++;
        preopConfig.putInteger("subsystem.count", num);
        cs.putInteger("subsystem.count", num);

        try {
            cs.commit(false);
        } catch (Exception e) {
            logger.warn("Unable to store server configuration: " + e, e);
        }

        IUser user = null;
        X509CertImpl[] certs = new X509CertImpl[1];
        logger.debug("CertUtil addUserCertificate starts");
        try {
            user = system.createUser(id);
            user.setFullName(id);
            user.setEmail("");
            user.setPassword("");
            user.setUserType("agentType");
            user.setState("1");
            user.setPhone("");
            system.addUser(user);
            logger.debug("CertUtil addUserCertificate: successfully add the user");

        } catch (ConflictingOperationException e) {
            logger.warn("CertUtil addUserCertificate: " + e, e);

        } catch (Exception e) {
            logger.warn("CertUtil addUserCertificate addUser: " + e, e);
        }

        try {
            user = system.getUser(id);
            certs[0] = cert;
            user.setX509Certificates(certs);

            system.addUserCert(user);
            logger.debug("CertUtil addUserCertificate: successfully add the user certificate");

        } catch (Exception e) {
            logger.warn("CertUtil addUserCertificate: " + e, e);
        }

        IGroup group = null;
        String groupName = "Subsystem Group";

        try {
            group = system.getGroupFromName(groupName);
            if (!group.isMember(id)) {
                group.addMemberName(id);
                system.modifyGroup(group);
                logger.debug("CertUtil addUserCertificate: update: successfully added the user to the group.");
            }
        } catch (Exception e) {
            logger.warn("CertUtil addUserCertificate update: modifyGroup: " + e, e);
        }
    }

    /*
     * formats a cert fingerprints
     */
    public static String fingerPrintFormat(String content) {
        if (content == null || content.length() == 0) {
            return "";
        }

        StringBuffer result = new StringBuffer();
        result.append("Fingerprints:\n");

        while (content.length() >= LINE_COUNT) {
            result.append(content.substring(0, LINE_COUNT));
            result.append("\n");
            content = content.substring(LINE_COUNT);
        }
        if (content.length() > 0)
            result.append(content);
        result.append("\n");

        return result.toString();
    }

    public static X509Certificate findCertificate(String fullnickname)
            throws Exception {

        CryptoManager cm = CryptoManager.getInstance();
        logger.debug("CertUtil: searching for cert " + fullnickname);

        try {
            return cm.findCertByNickname(fullnickname);

        } catch (ObjectNotFoundException e) {
            return null;
        }
    }

    public static void deleteCert(String tokenname, X509Certificate cert)
            throws Exception {

        logger.debug("CertUtil: deleting cert " + cert.getNickname());

        CryptoToken tok = CryptoUtil.getKeyStorageToken(tokenname);
        CryptoStore store = tok.getCryptoStore();

        if (store instanceof PK11Store) {
            PK11Store pk11store = (PK11Store) store;
            pk11store.deleteCertOnly(cert);
            logger.debug("CertUtil: cert deleted successfully");

        } else {
            logger.warn("CertUtil: unsupported crypto store: " + store.getClass().getName());
        }
    }
}
