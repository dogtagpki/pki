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

import java.security.cert.X509Certificate;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.cert.CrossCertPairSubsystem;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.selftests.SelfTestSubsystem;

public class CAEngine extends CMSEngine {

    public CAEngine() throws Exception {
        super("CA");
    }

    public static CAEngine getInstance() {
        return (CAEngine) CMS.getCMSEngine();
    }

    public EngineConfig createConfig(ConfigStorage storage) throws Exception {
        return new CAEngineConfig(storage);
    }

    public CAEngineConfig getConfig() {
        return (CAEngineConfig) mConfig;
    }

    public CAConfigurator createConfigurator() throws Exception {
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

    public X509Certificate[] getCertChain(X509CertImpl cert) throws Exception {

        ICertificateAuthority ca = (ICertificateAuthority) getSubsystem(ICertificateAuthority.ID);
        CertificateChain cachain = ca.getCACertChain();
        X509Certificate[] cacerts = cachain.getChain();

        X509CertImpl[] userChain = new X509CertImpl[cacerts.length + 1];
        userChain[0] = cert;
        for (int n = 0; n < cacerts.length; n++) {
            userChain[n + 1] = (X509CertImpl) cacerts[n];
        }

        return userChain;
    }

    public void startupSubsystems() throws EBaseException {

        super.startupSubsystems();

        // check serial number ranges
        ICertificateAuthority ca = (ICertificateAuthority) getSubsystem(ICertificateAuthority.ID);
        if (!isPreOpMode()) {
            logger.debug("CAEngine: checking request serial number ranges for the CA");
            ca.getRequestQueue().getRequestRepository().checkRanges();

            logger.debug("CAEngine: checking certificate serial number ranges");
            ca.getCertificateRepository().checkRanges();
        }
    }

    public ProfileSubsystem getProfileSubsystem() {
        return (ProfileSubsystem) getSubsystem(ProfileSubsystem.ID);
    }

    public ProfileSubsystem getProfileSubsystem(String name) {
        if (StringUtils.isEmpty(name)) {
            name = ProfileSubsystem.ID;
        }
        return (ProfileSubsystem) getSubsystem(name);
    }
}
