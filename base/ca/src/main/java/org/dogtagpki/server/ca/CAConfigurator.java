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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.ca;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;

import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.ca.CASigningUnit;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.csadmin.BootstrapProfile;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class CAConfigurator extends Configurator {

    public CAConfigurator(CMSEngine engine) {
        super(engine);
    }

    public RequestId createRequestID() throws Exception {
        CAEngine engine = CAEngine.getInstance();
        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        return requestRepository.createRequestID();
    }

    public CertId createCertID() throws Exception {
        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();
        BigInteger serialNumber = certificateRepository.getNextSerialNumber();
        return new CertId(serialNumber);
    }

    public void createCertRecord(X509CertImpl cert, RequestId requestID, String profileID) throws Exception {

        logger.info("CAConfigurator: Creating cert record 0x" + cert.getSerialNumber().toString(16));
        logger.info("CAConfigurator: - subject: " + cert.getSubjectDN());
        logger.info("CAConfigurator: - issuer: " + cert.getIssuerDN());

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();

        CertRecord certRecord = certificateRepository.createCertRecord(
                requestID,
                profileID,
                cert);

        certificateRepository.addCertificateRecord(certRecord);
    }

    @Override
    public X509CertImpl createCert(
            RequestId requestID,
            String keyAlgorithm,
            X509Key x509key,
            String profileID,
            PrivateKey signingPrivateKey,
            String signingAlgorithm,
            String certRequestType,
            byte[] binCertRequest,
            X500Name issuerName,
            X500Name subjectName) throws Exception {

        logger.info("CAConfigurator: Loading request record " + requestID.toHexString());

        CAEngine engine = CAEngine.getInstance();
        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        Request request = requestRepository.readRequest(requestID);

        CertId certID = createCertID();
        logger.info("CAConfigurator: Creating cert " + certID.toHexString());

        logger.info("CAConfigurator: - subject: " + subjectName);

        if (issuerName == null) { // local (not selfsign) cert

            CAEngineConfig engineConfig = engine.getConfig();
            CAConfig caConfig = engineConfig.getCAConfig();
            IConfigStore caSigningCfg = caConfig.getSubStore("signing");

            // create CA signing unit
            CASigningUnit signingUnit = new CASigningUnit();
            signingUnit.init(caSigningCfg, null);

            X509CertImpl caCertImpl = signingUnit.getCertImpl();
            CertificateSubjectName certSubjectName = caCertImpl.getSubjectObj();

            // use CA's issuer object to preserve DN encoding
            issuerName = (X500Name) certSubjectName.get(CertificateIssuerName.DN_NAME);
            signingPrivateKey = signingUnit.getPrivateKey();
        }

        CertificateIssuerName certIssuerName = new CertificateIssuerName(issuerName);
        logger.info("CAConfigurator: - issuer: " + certIssuerName);

        CertificateExtensions extensions = new CertificateExtensions();

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");
        String profilePath = instanceRoot + configurationRoot + profileID;

        logger.info("CAConfigurator: Loading " + profilePath);
        ConfigStore profileConfig = engine.loadConfigStore(profilePath);
        BootstrapProfile profile = new BootstrapProfile(profileConfig);

        Date date = new Date();
        X509CertInfo info = CryptoUtil.createX509CertInfo(
                x509key,
                certID.toBigInteger(),
                certIssuerName,
                subjectName,
                date,
                date,
                keyAlgorithm,
                extensions);

        profile.populate(request, info);

        X509CertImpl cert = CryptoUtil.signCert(signingPrivateKey, info, signingAlgorithm);
        logger.info("CAConfigurator: Cert info:\n" + info);

        createCertRecord(
                cert,
                request.getRequestId(),
                profileConfig.getString("profileIDMapping"));

        requestRepository.updateRequest(request, cert);

        request.setRequestStatus(RequestStatus.COMPLETE);
        requestRepository.updateRequest(request);

        return cert;
    }

    @Override
    public void initSubsystem() throws Exception {

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig engineConfig = engine.getConfig();

        CertificateAuthority ca = engine.getCA();
        ca.setConfig(engineConfig.getCAConfig());
        ca.initCertSigningUnit();
    }
}
