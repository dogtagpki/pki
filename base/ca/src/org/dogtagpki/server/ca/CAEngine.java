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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.ca;

import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import java.util.Locale;

import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.IEnrollProfile;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.cert.CrossCertPairSubsystem;
import com.netscape.cmscore.selftests.SelfTestSubsystem;

public class CAEngine extends CMSEngine {

    public CAEngine() throws Exception {
        super("CA");
    }

    public Configurator createConfigurator() throws Exception {
        return new CAConfigurator(this);
    }

    protected void loadSubsystems() throws EBaseException {

        super.loadSubsystems();

        if (isPreOpMode()) {
            // Disable some subsystems before database initialization
            // in pre-op mode to prevent misleading exceptions.

            setSubsystemEnabled(CertificateAuthority.ID, false);
            setSubsystemEnabled(CrossCertPairSubsystem.ID, false);
            setSubsystemEnabled(SelfTestSubsystem.ID, false);
        }
    }

    public byte[] getPKCS7(Locale locale, IRequest req) {
        try {
            X509CertImpl cert = req.getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);

            if (cert == null) {
                return null;
            }

            ICertificateAuthority ca = (ICertificateAuthority) getSubsystem(ICertificateAuthority.ID);
            CertificateChain cachain = ca.getCACertChain();
            X509Certificate[] cacerts = cachain.getChain();

            X509CertImpl[] userChain = new X509CertImpl[cacerts.length + 1];
            userChain[0] = cert;
            for (int n = 0; n < cacerts.length; n++) {
                userChain[n + 1] = (X509CertImpl) cacerts[n];
            }

            PKCS7 p7 = new PKCS7(new AlgorithmId[0],
                    new ContentInfo(new byte[0]),
                    userChain,
                    new SignerInfo[0]);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            p7.encodeSignedData(bos);
            return bos.toByteArray();

        } catch (Exception e) {
            return null;
        }
    }

    public void startupSubsystems() throws EBaseException {

        super.startupSubsystems();

        // check serial number ranges
        ICertificateAuthority ca = (ICertificateAuthority) getSubsystem(ICertificateAuthority.ID);
        if (!isPreOpMode()) {
            logger.debug("CMSEngine: checking request serial number ranges for the CA");
            ca.getRequestQueue().getRequestRepository().checkRanges();

            logger.debug("CMSEngine: checking certificate serial number ranges");
            ca.getCertificateRepository().checkRanges();
        }
    }
}
