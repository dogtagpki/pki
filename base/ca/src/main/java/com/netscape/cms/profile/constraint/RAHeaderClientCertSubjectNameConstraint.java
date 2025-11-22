//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.profile.constraint;

import java.security.cert.X509Certificate;
import java.util.Locale;

import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;

/**
 * Subject name constraint for clients authenticated via RA.
 *
 * This constraint is used when the RA (e.g., EST with CMCAuthForEST) stores the
 * RA-authenticated client certificate in SessionContext instead of using profile input.
 *
 * If the RA-authenticated client certificate belongs to an agent (member of "Certificate Manager Agents"),
 * any subject name is allowed. Otherwise, the subject name must match the RA-authenticated client certificate subject.
 *
 * @author cfu
 */
public class RAHeaderClientCertSubjectNameConstraint extends EnrollConstraint {
    private static final Logger logger = LoggerFactory.getLogger(RAHeaderClientCertSubjectNameConstraint.class);
    private static final String CONFIG_PATTERN = "pattern";

    public RAHeaderClientCertSubjectNameConstraint() {
        // configuration names
        addConfigName(CONFIG_PATTERN);
    }

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_PATTERN)) {
            return new Descriptor(IDescriptor.STRING,
                    null, null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SUBJECT_NAME_PATTERN"));
        }
        return null;
    }

    @Override
    public void validate(Request request, X509CertInfo info) throws ERejectException {
        String method = "RAHeaderClientCertSubjectNameConstraint: validate: ";
        logger.debug(method + "start");

        CertificateSubjectName sn = null;

        try {
            sn = info.getSubjectObj();
            logger.debug(method + "cert subject {}", sn.toString());
        } catch (Exception e) {
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_SUBJECT_NAME_NOT_FOUND"));
        }

        // Get RA-authenticated client certificate from SessionContext (stored by CMCAuthForEST)
        SessionContext context = SessionContext.getExistingContext();
        if (context == null) {
            logger.warn(method + "No session context available");
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_SUBJECT_NAME_CLIENT_NOT_AVAILABLE"));
        }

        Object clientCertObj = context.get(SessionContext.SSL_CLIENT_CERT);
        if (!(clientCertObj instanceof X509Certificate)) {
            logger.warn(method + "No RA-authenticated client certificate found in session context");
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_SUBJECT_NAME_CLIENT_NOT_AVAILABLE"));
        }

        X509CertImpl cert = (X509CertImpl) clientCertObj;
        logger.debug(method + "Found RA-authenticated client cert in session context");

        CertificateSubjectName snClient = cert.getSubjectObj();
        logger.debug(method + "Client cert subject {}", snClient);

        // If client is an agent, allow any subject name
        if (isAgentCert(cert)) {
            logger.debug(method + "Client is an agent, allowing any subject name");
            return;
        }

        // If client subject matches requested subject, allow it
        if (snClient.toString().equals(sn.toString())) {
            logger.debug(method + "Client subject matches requested subject");
            return;
        }

        // For non-agents with different subject, reject
        logger.warn(method + "Subject name mismatch for non-agent client");
        throw new ERejectException(
                CMS.getUserMessage(getLocale(request),
                    "CMS_PROFILE_SUBJECT_NAME_NOT_MATCHED", sn.toString()));
    }

    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale,
                "CMS_PROFILE_CONSTRAINT_SUBJECT_NAME_TEXT",
                getConfig(CONFIG_PATTERN));
    }
}
