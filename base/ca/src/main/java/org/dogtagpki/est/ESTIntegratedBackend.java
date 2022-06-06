package org.dogtagpki.est;

import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.CertificateChain;

import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.servlet.cert.CertEnrollmentRequestFactory;
import com.netscape.cms.servlet.cert.EnrollmentProcessor;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.request.Request;

import org.dogtag.util.cert.CertUtil;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.ICertificateAuthority;

/**
 * EST backend for integrating the EST service in the CA subsystem.
 *
 * @author Fraser Tweedale
 */
public class ESTIntegratedBackend implements ESTBackend {

    @Override
    public CertificateChain cacerts(Optional<String> label) {
        CAEngine engine = CAEngine.getInstance();
        ICertificateAuthority ca = engine.getCA();
        return ca.getCACertChain();
        // TODO use label to select LWCA;
    }

    @Override
    public ESTEnrollResult simpleenroll(Optional<String> label, PKCS10 csr) {
        CAEngine engine = CAEngine.getInstance();
        ICertificateAuthority ca = engine.getCA();
        // TODO use label to select LWCA;
        AuthorityID authorityID = ca.getAuthorityID();

        // TODO don't hard-code the auth token
        AuthToken authToken = new AuthToken(null);
        authToken.set(AuthToken.UID, "ipara");
        String[] groups = { "Certificate Manager Agents" };
        authToken.set(AuthToken.GROUPS, groups);

        Locale locale = Locale.getDefault();

        ProfileSubsystem ps = engine.getProfileSubsystem();
        String profileId = "caIPAserviceCert";  // TODO avoid hard-coding

        Map<String, Object> resultMap;
        try {
            ArgBlock argBlock = new ArgBlock();
            argBlock.set("cert_request_type", "pkcs10");
            argBlock.set("cert_request", CertUtil.toPEM(csr));

            Profile profile = ps.getProfile(profileId);
            CertEnrollmentRequest certRequest =
                CertEnrollmentRequestFactory.create(argBlock, profile, locale);
            EnrollmentProcessor processor = new EnrollmentProcessor("EST enrollment", locale);
            resultMap = processor.processEnrollment(
                certRequest, null, authorityID, null, authToken);
        } catch (Throwable e) {
            return ESTEnrollResult.failure(e);
        }

        Request[] requests = (Request[]) resultMap.get(CAProcessor.ARG_REQUESTS);
        Request request = requests[0];

        Integer result = request.getExtDataInInteger(Request.RESULT);
        if (result != null && !result.equals(Request.RES_SUCCESS)) {
            return ESTEnrollResult.failure(
                new EBaseException("Unable to generate signing certificate: " + result));
        }

        RequestStatus requestStatus = request.getRequestStatus();
        if (requestStatus != RequestStatus.COMPLETE) {
            // The request did not complete.  Inference: something
            // incorrect in the request (e.g. profile constraint
            // violated).
            String msg = "Unable to generate signing certificate: " + requestStatus;
            String errorMsg = request.getExtDataInString(Request.ERROR);
            if (errorMsg != null) {
                msg += ": " + errorMsg;
            }
            return ESTEnrollResult.failure(new BadRequestDataException(msg));
        }

        return ESTEnrollResult.success(
            request.getExtDataInCert(Request.REQUEST_ISSUED_CERT));
    }

    @Override
    public ESTEnrollResult simplereenroll(Optional<String> label, PKCS10 csr) {
        return ESTEnrollResult.failure(new RuntimeException("not implemented)"));
    }

}
