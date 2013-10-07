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
package com.netscape.cms.profile.constraint;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Locale;

import netscape.security.x509.CRLExtensions;
import netscape.security.x509.CRLReasonExtension;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.Extension;
import netscape.security.x509.KeyUsageExtension;
import netscape.security.x509.RevocationReason;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.dbs.certdb.IRevocationInfo;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cms.profile.def.SubjectNameDefault;
import com.netscape.cms.profile.def.UserSubjectNameDefault;

/**
 * This class implements the unique subject name constraint.
 * It checks if the subject name in the certificate is
 * unique in the internal database, ie, no two certificates
 * have the same subject name.
 *
 * @version $Revision$, $Date$
 */
public class UniqueSubjectNameConstraint extends EnrollConstraint {

    public static final String CONFIG_KEY_USAGE_EXTENSION_CHECKING =
            "enableKeyUsageExtensionChecking";
    private boolean mKeyUsageExtensionChecking = true;

    public UniqueSubjectNameConstraint() {
        addConfigName(CONFIG_KEY_USAGE_EXTENSION_CHECKING);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_KEY_USAGE_EXTENSION_CHECKING)) {
            return new Descriptor(IDescriptor.BOOLEAN, null, "true",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CONFIG_KEY_USAGE_EXTENSION_CHECKING"));
        }
        return null;
    }

    public String getDefaultConfig(String name) {
        return null;
    }

    /**
     * Checks if the key extension in the issued certificate
     * is the same as the one in the certificate template.
     */
    private boolean sameKeyUsageExtension(ICertRecord rec,
            X509CertInfo certInfo) {
        X509CertImpl impl = rec.getCertificate();
        boolean bits[] = impl.getKeyUsage();

        CertificateExtensions extensions = null;

        try {
            extensions = (CertificateExtensions)
                    certInfo.get(X509CertInfo.EXTENSIONS);
        } catch (IOException e) {
        } catch (java.security.cert.CertificateException e) {
        }
        KeyUsageExtension ext = null;

        if (extensions == null) {
            if (bits != null)
                return false;
        } else {
            try {
                ext = (KeyUsageExtension) extensions.get(
                        KeyUsageExtension.NAME);
            } catch (IOException e) {
                // extension isn't there.
            }

            if (ext == null) {
                if (bits != null)
                    return false;
            } else {
                boolean[] InfoBits = ext.getBits();

                if (InfoBits == null) {
                    if (bits != null)
                        return false;
                } else {
                    if (bits == null)
                        return false;
                    if (InfoBits.length != bits.length) {
                        return false;
                    }
                    for (int i = 0; i < InfoBits.length; i++) {
                        if (InfoBits[i] != bits[i])
                            return false;
                    }
                }
            }
        }
        return true;
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     *
     * Rules are as follows:
     * If the subject name is not unique, then the request will be rejected unless:
     * 1. the certificate is expired or expired_revoked
     * 2. the certificate is revoked and the revocation reason is not "on hold"
     * 3. the keyUsageExtension bits are different and enableKeyUsageExtensionChecking=true (default)
     */
    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {
        CMS.debug("UniqueSubjectNameConstraint: validate start");
        CertificateSubjectName sn = null;
        IAuthority authority = (IAuthority) CMS.getSubsystem("ca");

        mKeyUsageExtensionChecking = getConfigBoolean(CONFIG_KEY_USAGE_EXTENSION_CHECKING);
        ICertificateRepository certdb = null;
        if (authority != null && authority instanceof ICertificateAuthority) {
            ICertificateAuthority ca = (ICertificateAuthority) authority;
            certdb = ca.getCertificateRepository();
        }

        try {
            sn = (CertificateSubjectName) info.get(X509CertInfo.SUBJECT);
        } catch (Exception e) {
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_SUBJECT_NAME_NOT_FOUND"));
        }

        String certsubjectname = null;
        if (sn == null)
            throw new ERejectException(
                    CMS.getUserMessage(getLocale(request),
                            "CMS_PROFILE_SUBJECT_NAME_NOT_FOUND"));
        else {
            certsubjectname = sn.toString();
            String filter = "x509Cert.subject=" + certsubjectname;
            Enumeration<ICertRecord> sameSubjRecords = null;
            try {
                sameSubjRecords = certdb.findCertRecords(filter);
            } catch (EBaseException e) {
                CMS.debug("UniqueSubjectNameConstraint exception: " + e.toString());
            }
            while (sameSubjRecords != null && sameSubjRecords.hasMoreElements()) {
                ICertRecord rec = sameSubjRecords.nextElement();
                String status = rec.getStatus();

                IRevocationInfo revocationInfo = rec.getRevocationInfo();
                RevocationReason reason = null;

                if (revocationInfo != null) {
                    CRLExtensions crlExts = revocationInfo.getCRLEntryExtensions();

                    if (crlExts != null) {
                        Enumeration<Extension> enumx = crlExts.getElements();

                        while (enumx.hasMoreElements()) {
                            Extension ext = enumx.nextElement();

                            if (ext instanceof CRLReasonExtension) {
                                reason = ((CRLReasonExtension) ext).getReason();
                            }
                        }
                    }
                }

                if (status.equals(ICertRecord.STATUS_EXPIRED) || status.equals(ICertRecord.STATUS_REVOKED_EXPIRED)) {
                    continue;
                }

                if (status.equals(ICertRecord.STATUS_REVOKED) && reason != null &&
                        (!reason.equals(RevocationReason.CERTIFICATE_HOLD))) {
                    continue;
                }

                if (mKeyUsageExtensionChecking && !sameKeyUsageExtension(rec, info)) {
                    continue;
                }

                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_SUBJECT_NAME_NOT_UNIQUE",
                                certsubjectname));
            }
        }
        CMS.debug("UniqueSubjectNameConstraint: validate end");
    }

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_KEY_USAGE_EXTENSION_CHECKING)
        };
        return CMS.getUserMessage(locale,
                "CMS_PROFILE_CONSTRAINT_UNIQUE_SUBJECT_NAME_TEXT",
                params);
    }

    public boolean isApplicable(IPolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        if (def instanceof SubjectNameDefault)
            return true;
        if (def instanceof UserSubjectNameDefault)
            return true;
        return false;
    }
}
