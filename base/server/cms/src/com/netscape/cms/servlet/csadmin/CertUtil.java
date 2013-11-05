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

import javax.servlet.http.HttpServletResponse;

import netscape.security.pkcs.PKCS10;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.velocity.context.Context;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.profile.CertInfoProfile;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.http.HttpClient;
import com.netscape.cmsutil.http.HttpRequest;
import com.netscape.cmsutil.http.HttpResponse;
import com.netscape.cmsutil.http.JssSSLSocketFactory;
import com.netscape.cmsutil.xml.XMLObject;

public class CertUtil {
    static final int LINE_COUNT = 76;

    public static X509CertImpl createRemoteCert(String hostname,
            int port, String content, HttpServletResponse response, WizardPanelBase panel)
            throws IOException {
        HttpClient httpclient = new HttpClient();
        String c = null;
        CMS.debug("CertUtil createRemoteCert: content " + content);
        try {
            JssSSLSocketFactory factory = new JssSSLSocketFactory();

            httpclient = new HttpClient(factory);
            httpclient.connect(hostname, port);
            HttpRequest httprequest = new HttpRequest();

            httprequest.setMethod(HttpRequest.POST);
            httprequest.setURI("/ca/ee/ca/profileSubmit");
            httprequest.setHeader("user-agent", "HTTPTool/1.0");
            httprequest.setHeader("content-length", "" + content.length());
            httprequest.setHeader("content-type",
                    "application/x-www-form-urlencoded");
            httprequest.setContent(content);
            HttpResponse httpresponse = httpclient.send(httprequest);

            c = httpresponse.getContent();
        } catch (Exception e) {
            CMS.debug("CertUtil createRemoteCert: " + e.toString());
            throw new IOException(e.toString());
        }

        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug("CertUtil::createRemoteCert() - "
                             + "Exception=" + e.toString());
                    throw new IOException(e.toString());
                }
                String status = parser.getValue("Status");

                CMS.debug("CertUtil createRemoteCert: status=" + status);
                if (status.equals("2")) {
                    //relogin to the security domain
                    panel.reloginSecurityDomain(response);
                    return null;
                } else if (!status.equals("0")) {
                    String error = parser.getValue("Error");
                    throw new IOException(error);
                }

                String b64 = parser.getValue("b64");

                CMS.debug("CertUtil createRemoteCert: " + b64);
                b64 = CryptoUtil.normalizeCertAndReq(b64);
                byte[] b = CryptoUtil.base64Decode(b64);

                return new X509CertImpl(b);
            } catch (Exception e) {
                CMS.debug("CertUtil createRemoteCert: " + e.toString());
                throw new IOException(e.toString());
            }
        }

        return null;
    }

    public static String getPKCS10(IConfigStore config, String prefix,
            Cert certObj, Context context) throws IOException {
        String certTag = certObj.getCertTag();

        X509Key pubk = null;
        try {
            String pubKeyType = config.getString(
                        prefix + certTag + ".keytype");
            String algorithm = config.getString(
                        prefix + certTag + ".keyalgorithm");
            if (pubKeyType.equals("rsa")) {
                String pubKeyModulus = config.getString(
                        prefix + certTag + ".pubkey.modulus");
                String pubKeyPublicExponent = config.getString(
                        prefix + certTag + ".pubkey.exponent");
                pubk = CryptoUtil.getPublicX509Key(
                        CryptoUtil.string2byte(pubKeyModulus),
                        CryptoUtil.string2byte(pubKeyPublicExponent));
            } else if (pubKeyType.equals("ecc")) {
                String pubKeyEncoded = config.getString(
                        prefix + certTag + ".pubkey.encoded");
                pubk = CryptoUtil.getPublicX509ECCKey(
                        CryptoUtil.string2byte(pubKeyEncoded));
            } else {
                CMS.debug("CertRequestPanel::getPKCS10() - "
                        + "public key type is unsupported!");
                throw new IOException("public key type is unsupported");
            }

            if (pubk != null) {
                CMS.debug("CertRequestPanel: got public key");
            } else {
                CMS.debug("CertRequestPanel: error getting public key null");
                throw new IOException("public key is null");
            }
            // get private key
            String privKeyID = config.getString(prefix + certTag + ".privkey.id");
            byte[] keyIDb = CryptoUtil.string2byte(privKeyID);

            PrivateKey privk = CryptoUtil.findPrivateKeyFromID(keyIDb);

            if (privk != null) {
                CMS.debug("CertRequestPanel: got private key");
            } else {
                CMS.debug("CertRequestPanel: error getting private key null");
            }

            // construct cert request
            String dn = config.getString(prefix + certTag + ".dn");

            PKCS10 certReq = null;
            certReq = CryptoUtil.createCertificationRequest(dn, pubk,
                    privk, algorithm);
            byte[] certReqb = certReq.toByteArray();
            String certReqs = CryptoUtil.base64Encode(certReqb);

            return certReqs;
        } catch (Throwable e) {
            CMS.debug(e);
            if (context != null) {
                context.put("errorString", e.toString());
            }
            CMS.debug("CertUtil getPKCS10: " + e.toString());
            throw new IOException(e.toString());
        }
    }

    /*
     * create requests so renewal can work on these initial certs
     */
    public static IRequest createLocalRequest(IRequestQueue queue, String serialNum, X509CertInfo info)
            throws EBaseException {
        //        RequestId rid = new RequestId(serialNum);
        // just need a request, no need to get into a queue
        //        IRequest r = new EnrollmentRequest(rid);
        CMS.debug("CertUtil: createLocalRequest for serial: " + serialNum);
        IRequest req = queue.newRequest("enrollment");
        CMS.debug("certUtil: newRequest called");
        req.setExtData("profile", "true");
        req.setExtData("requestversion", "1.0.0");
        req.setExtData("req_seq_num", "0");
        req.setExtData(IEnrollProfile.REQUEST_CERTINFO, info);
        req.setExtData(IEnrollProfile.REQUEST_EXTENSIONS,
                    new CertificateExtensions());
        req.setExtData("requesttype", "enrollment");
        req.setExtData("requestor_name", "");
        req.setExtData("requestor_email", "");
        req.setExtData("requestor_phone", "");
        req.setExtData("profileRemoteHost", "");
        req.setExtData("profileRemoteAddr", "");
        req.setExtData("requestnotes", "");
        req.setExtData("isencryptioncert", "false");
        req.setExtData("profileapprovedby", "system");

        // mark request as complete
        CMS.debug("certUtil: calling setRequestStatus");
        req.setRequestStatus(RequestStatus.COMPLETE);

        return req;
    }

    /**
     * update local cert request with the actual request
     * called from CertRequestPanel.java
     */
    public static void updateLocalRequest(IConfigStore config, String certTag, String certReq, String reqType,
            String subjectName) {
        try {
            CMS.debug("Updating local request... certTag=" + certTag);
            RequestId rid = new RequestId(config.getString("preop.cert." + certTag + ".reqId"));

            ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem(
                    ICertificateAuthority.ID);

            IRequestQueue queue = ca.getRequestQueue();
            if (queue != null) {
                IRequest req = queue.findRequest(rid);
                if (req != null) {
                    if (!certReq.equals(""))
                        req.setExtData("cert_request", certReq);
                    req.setExtData("cert_request_type", reqType);
                    if (subjectName != null) {
                        req.setExtData("subject", subjectName);
                        new X500Name(subjectName); // check for errors
                    }
                }
                queue.updateRequest(req);
            } else {
                CMS.debug("CertUtil:updateLocalRequest - request queue = null");
            }
        } catch (Exception e) {
            CMS.debug("CertUtil:updateLocalRequest - Exception:" + e.toString());
        }
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

    public static String getAdminProfileAlgorithm(IConfigStore config) throws EBaseException, FileNotFoundException,
            IOException {
        String caSigningKeyType = config.getString("preop.cert.signing.keytype", "rsa");
        String pfile = config.getString("profile.caAdminCert.config");
        Properties props = new Properties();
        props.load(new FileInputStream(pfile));

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
            algsAllowed = StringUtils.split(config.getString("ca.profiles.defaultSigningAlgsAllowed",
                    "SHA256withRSA,SHA256withEC,SHA1withDSA"), ",");
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

    public static X509CertImpl createLocalCert(IConfigStore config, X509Key x509key,
            String prefix, String certTag, String type, Context context) throws IOException {

        CMS.debug("Creating local certificate... certTag=" + certTag);
        String profile = null;

        try {
            profile = config.getString(prefix + certTag + ".profile");
        } catch (Exception e) {
        }

        X509CertImpl cert = null;
        ICertificateAuthority ca = null;
        ICertificateRepository cr = null;
        RequestId reqId = null;
        String profileId = null;
        IRequestQueue queue = null;
        IRequest req = null;

        try {
            String dn = config.getString(prefix + certTag + ".dn");
            String keyAlgorithm = null;
            Date date = new Date();

            X509CertInfo info = null;

            if (certTag.equals("admin")) {
                keyAlgorithm = getAdminProfileAlgorithm(config);
            } else {
                keyAlgorithm = config.getString(prefix + certTag + ".keyalgorithm");
            }
            ca = (ICertificateAuthority) CMS.getSubsystem(
                    ICertificateAuthority.ID);
            cr = ca.getCertificateRepository();
            BigInteger serialNo = cr.getNextSerialNumber();
            if (type.equals("selfsign")) {
                CMS.debug("Creating local certificate... issuerdn=" + dn);
                CMS.debug("Creating local certificate... dn=" + dn);
                info = CryptoUtil.createX509CertInfo(x509key, serialNo, dn, dn, date, date, keyAlgorithm);
            } else {
                String issuerdn = config.getString("preop.cert.signing.dn", "");
                CMS.debug("Creating local certificate... issuerdn=" + issuerdn);
                CMS.debug("Creating local certificate... dn=" + dn);

                info = CryptoUtil.createX509CertInfo(x509key, serialNo, issuerdn, dn, date, date, keyAlgorithm);
            }
            CMS.debug("Cert Template: " + info.toString());

            String instanceRoot = config.getString("instanceRoot");

            String configurationRoot = config.getString("configurationRoot");

            CertInfoProfile processor = new CertInfoProfile(
                    instanceRoot + configurationRoot + profile);

            // cfu - create request to enable renewal
            try {
                queue = ca.getRequestQueue();
                if (queue != null) {
                    req = createLocalRequest(queue, serialNo.toString(), info);
                    CMS.debug("CertUtil profile name= " + profile);
                    req.setExtData("req_key", x509key.toString());

                    // store original profile id in cert request
                    int idx = profile.lastIndexOf('.');
                    if (idx == -1) {
                        CMS.debug("CertUtil profileName contains no .");
                        req.setExtData("origprofileid", profile);
                    } else {
                        String name = profile.substring(0, idx);
                        req.setExtData("origprofileid", name);
                    }

                    // store mapped profile ID for use in renewal
                    profileId = processor.getProfileIDMapping();
                    req.setExtData("profileid", profileId);
                    req.setExtData("profilesetid", processor.getProfileSetIDMapping());

                    reqId = req.getRequestId();
                    config.putString("preop.cert." + certTag + ".reqId", reqId.toString());
                } else {
                    CMS.debug("certUtil: requestQueue null");
                }
            } catch (Exception e) {
                CMS.debug("Creating local request exception:" + e.toString());
            }

            processor.populate(req, info);

            String caPriKeyID = config.getString(
                    prefix + "signing" + ".privkey.id");
            byte[] keyIDb = CryptoUtil.string2byte(caPriKeyID);
            PrivateKey caPrik = CryptoUtil.findPrivateKeyFromID(
                    keyIDb);

            if (caPrik == null) {
                CMS.debug("CertUtil::createSelfSignedCert() - "
                         + "CA private key is null!");
                throw new IOException("CA private key is null");
            } else {
                CMS.debug("CertUtil createSelfSignedCert: got CA private key");
            }

            String keyAlgo = x509key.getAlgorithm();
            CMS.debug("key algorithm is " + keyAlgo);
            String caSigningKeyType =
                    config.getString("preop.cert.signing.keytype", "rsa");
            String caSigningKeyAlgo = "";
            if (type.equals("selfsign")) {
                caSigningKeyAlgo = config.getString("preop.cert.signing.keyalgorithm", "SHA256withRSA");
            } else {
                caSigningKeyAlgo = config.getString("preop.cert.signing.signingalgorithm", "SHA256withRSA");
            }

            CMS.debug("CA Signing Key type " + caSigningKeyType);
            CMS.debug("CA Signing Key algorithm " + caSigningKeyAlgo);

            if (caSigningKeyType.equals("ecc")) {
                CMS.debug("CA signing cert is ECC");
                cert = CryptoUtil.signECCCert(caPrik, info,
                        caSigningKeyAlgo);
            } else {
                CMS.debug("CA signing cert is not ecc");
                cert = CryptoUtil.signCert(caPrik, info,
                        caSigningKeyAlgo);
            }

            if (cert != null) {
                CMS.debug("CertUtil createSelfSignedCert: got cert signed");
            }
        } catch (Exception e) {
            CMS.debug(e);
            CMS.debug("NamePanel configCert() exception caught:" + e.toString());
        }

        if (cr == null) {
            if (context != null) {
                context.put("errorString", "Ceritifcate Authority is not ready to serve.");
            }
            throw new IOException("Ceritifcate Authority is not ready to serve.");
        }

        ICertRecord record = null;
        try {
            MetaInfo meta = new MetaInfo();
            if (reqId != null) {
                meta.set(ICertRecord.META_REQUEST_ID, reqId.toString());
            }

            meta.set(ICertRecord.META_PROFILE_ID, profileId);
            record = cr.createCertRecord(
                    cert.getSerialNumber(), cert, meta);
        } catch (Exception e) {
            CMS.debug(
                    "NamePanel configCert: failed to add metainfo. Exception: " + e.toString());
        }

        try {
            cr.addCertificateRecord(record);
            CMS.debug(
                    "NamePanel configCert: finished adding certificate record.");
        } catch (Exception e) {
            CMS.debug(
                    "NamePanel configCert: failed to add certificate record. Exception: "
                            + e.toString());
            try {
                cr.deleteCertificateRecord(record.getSerialNumber());
                cr.addCertificateRecord(record);
            } catch (Exception ee) {
                CMS.debug("NamePanel update: Exception: " + ee.toString());
            }
        }

        if (req != null) {
            // update request with cert
            req.setExtData(IEnrollProfile.REQUEST_ISSUED_CERT, cert);

            // store request in db
            try {
                CMS.debug("certUtil: before updateRequest");
                if (queue != null) {
                    queue.updateRequest(req);
                }
            } catch (Exception e) {
                CMS.debug("Exception in updateRequest" + e);
            }
        }

        return cert;
    }

    public static void addUserCertificate(X509CertImpl cert) {
        IConfigStore cs = CMS.getConfigStore();
        int num = 0;
        try {
            num = cs.getInteger("preop.subsystem.count", 0);
        } catch (Exception e) {
        }
        IUGSubsystem system = (IUGSubsystem) (CMS.getSubsystem(IUGSubsystem.ID));
        String id = "user" + num;

        try {
            String sysType = cs.getString("cs.type", "");
            String machineName = cs.getString("machineName", "");
            String securePort = cs.getString("service.securePort", "");
            id = sysType + "-" + machineName + "-" + securePort;
        } catch (Exception e1) {
            // ignore
        }

        num++;
        cs.putInteger("preop.subsystem.count", num);
        cs.putInteger("subsystem.count", num);

        try {
            cs.commit(false);
        } catch (Exception e) {
        }

        IUser user = null;
        X509CertImpl[] certs = new X509CertImpl[1];
        CMS.debug("CertUtil addUserCertificate starts");
        try {
            user = system.createUser(id);
            user.setFullName(id);
            user.setEmail("");
            user.setPassword("");
            user.setUserType("agentType");
            user.setState("1");
            user.setPhone("");
            system.addUser(user);
            CMS.debug("CertUtil addUserCertificate: successfully add the user");

        } catch (ConflictingOperationException e) {
            CMS.debug("CertUtil addUserCertificate" + e.toString());
            // ignore

        } catch (Exception e) {
            CMS.debug("CertUtil addUserCertificate addUser " + e.toString());
        }

        try {
            user = system.getUser(id);
            certs[0] = cert;
            user.setX509Certificates(certs);

            system.addUserCert(user);
            CMS.debug("CertUtil addUserCertificate: successfully add the user certificate");

        } catch (Exception e) {
            CMS.debug("CertUtil addUserCertificate exception=" + e.toString());
        }

        IGroup group = null;
        String groupName = "Subsystem Group";

        try {
            group = system.getGroupFromName(groupName);
            if (!group.isMember(id)) {
                group.addMemberName(id);
                system.modifyGroup(group);
                CMS.debug("CertUtil addUserCertificate: update: successfully added the user to the group.");
            }
        } catch (Exception e) {
            CMS.debug("CertUtil addUserCertificate update: modifyGroup " + e.toString());
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

    public static boolean privateKeyExistsOnToken(String certTag,
            String tokenname, String nickname) {
        IConfigStore cs = CMS.getConfigStore();
        String givenid = "";
        try {
            givenid = cs.getString("preop.cert." + certTag + ".privkey.id");
        } catch (Exception e) {
            CMS.debug("CertUtil privateKeyExistsOnToken: we did not generate private key yet.");
            return false;
        }

        String fullnickname = nickname;

        if (!tokenname.equals("internal") && !tokenname.equals("Internal Key Storage Token")) {
            fullnickname = tokenname + ":" + nickname;
        }

        X509Certificate cert = null;
        CryptoManager cm = null;
        try {
            cm = CryptoManager.getInstance();
            cert = cm.findCertByNickname(fullnickname);
        } catch (Exception e) {
            CMS.debug("CertUtil privateKeyExistsOnToken: nickname=" + fullnickname + " Exception:" + e.toString());
            return false;
        }

        PrivateKey privKey = null;
        try {
            privKey = cm.findPrivKeyByCert(cert);
        } catch (Exception e) {
            CMS.debug("CertUtil privateKeyExistsOnToken: cant find private key ("
                    + fullnickname + ") exception: " + e.toString());
            return false;
        }

        if (privKey == null) {
            CMS.debug("CertUtil privateKeyExistsOnToken: cant find private key (" + fullnickname + ")");
            return false;
        } else {
            String str = "";
            try {
                str = CryptoUtil.byte2string(privKey.getUniqueID());
            } catch (Exception e) {
                CMS.debug("CertUtil privateKeyExistsOnToken: encode string Exception: " + e.toString());
            }

            if (str.equals(givenid)) {
                CMS.debug("CertUtil privateKeyExistsOnToken: find the private key on the token.");
                return true;
            }
        }

        return false;
    }
}
