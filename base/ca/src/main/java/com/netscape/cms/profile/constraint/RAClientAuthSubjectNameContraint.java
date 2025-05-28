//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.profile.constraint;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Locale;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.usrgrp.Certificates;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.cms.profile.input.RAClientAuthInfoInput;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.usrgrp.ExactMatchCertUserLocator;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;

import netscape.ldap.LDAPException;

/**
 * Subject name constraints for clients authenticated by an RA.
 *
 * If RA sends client authentication information with the enrolment request, these can
 * be used to limit the the new certificate subject name to the same used by the client for
 * authentication or to its name.
 */
public class RAClientAuthSubjectNameContraint extends EnrollConstraint {
    private static final Logger logger = LoggerFactory.getLogger(RAClientAuthSubjectNameContraint.class);
    private static final String CONFIG_PATTERN = "pattern";

    public RAClientAuthSubjectNameContraint() {
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
        logger.debug("RAClientSubjectNameContraint: validate start");
        CertificateSubjectName sn = null;

        try {
            sn = info.getSubjectObj();
            logger.debug("RAClientSubjectNameContraint: validate cert subject {}",
                         sn.toString());
        } catch (Exception e) {
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_SUBJECT_NAME_NOT_FOUND"));
        }

        String name = request.getExtDataInString(RAClientAuthInfoInput.NAME);
        String uid = request.getExtDataInString(RAClientAuthInfoInput.UID);
        String strCert = request.getExtDataInString(RAClientAuthInfoInput.CERT);
        logger.debug("RAClientSubjectNameContraint: Client {} with cert {}", name, strCert);
        if ((name == null || name.isBlank()) &&
                (uid == null || uid.isBlank()) &&
                (strCert == null || strCert.isBlank())) {
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                        "CMS_PROFILE_SUBJECT_NAME_CLIENT_NOT_AVAILABLE"));
        }

        if (strCert != null && !strCert.isBlank()) {
            X509CertImpl cert = null;
            CertificateSubjectName snClient = null;
            try {
                cert = new X509CertImpl(Utils.base64decode(strCert));
            } catch (CertificateException e) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_SUBJECT_NAME_NOT_MATCHED") + e);
            }
            snClient = cert.getSubjectObj();
            logger.debug("RAClientSubjectNameContraint: Client cert subject {}", snClient);

            if (isAgentCert(cert) || snClient.toString().equals(sn.toString()))
                return;

        } else if ((name != null && !name.isBlank()) ||
                (uid != null && !uid.isBlank())) {
            X500Name certName = sn.getX500Name();
            X500Name sourceName = null;
            String pattern = getConfig(CONFIG_PATTERN);
            if (pattern == null || pattern.isBlank()) {
                pattern = "CN=$ra_client_name$";
            }
            try {
                pattern = pattern.replace("$ra_client_name$", name);
                pattern = pattern.replace("$ra_client_uid$", uid);
                sourceName = new X500Name(pattern);
            } catch (IOException e) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_SUBJECT_NAME_NOT_MATCHED") + e);
            }
            if (certName.equals(sourceName))
                return;
        }
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

    private boolean isAgentCert(X509CertImpl cert) {
        ExactMatchCertUserLocator mcu = new ExactMatchCertUserLocator();
        CAEngine engine = CAEngine.getInstance();
        mcu.setCMSEngine(engine);
        X509CertImpl[] certList = new X509CertImpl[1];
        certList[0] = cert;
        Certificates ci = new Certificates(certList);
        User user;
        try {
            user = mcu.locateUser(ci);
        } catch (EUsrGrpException | LDAPException e) {
            logger.debug("RAClientAuthSubjectNameConstraint: isAgentCert", e);
            return false;
        }
        UGSubsystem uggroup = engine.getUGSubsystem();
        if (uggroup.isMemberOf(user, "Certificate Manager Agents")) {
            logger.debug("RAClientAuthSubjectNameConstraint: authorise agent {}", user.getUserID());
            return true;
        }
        return false;
    }
}
