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
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.netscape.security.x509.CertificateChain;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.cert.CrossCertPairSubsystem;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.selftests.SelfTestSubsystem;

@WebListener
public class CAEngine extends CMSEngine implements ServletContextListener {

    public static Map<AuthorityID, CertificateAuthority> authorities =
            Collections.synchronizedSortedMap(new TreeMap<AuthorityID, CertificateAuthority>());

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

    public X509Certificate[] getCertChain(X509Certificate cert) throws Exception {

        CertificateAuthority ca = getCA();
        CertificateChain caChain = ca.getCACertChain();
        X509Certificate[] caCerts = caChain.getChain();

        if (CertUtils.certInCertChain(caCerts, cert)) {
            return Arrays.copyOf(caCerts, caCerts.length);
        }

        X509Certificate[] certChain = new X509Certificate[caCerts.length + 1];
        certChain[0] = cert;
        System.arraycopy(caCerts, 0, certChain, 1, caCerts.length);

        return certChain;
    }

    public void startupSubsystems() throws EBaseException {

        super.startupSubsystems();

        // check serial number ranges
        CertificateAuthority ca = getCA();
        if (!isPreOpMode()) {
            logger.debug("CAEngine: checking request serial number ranges for the CA");
            ca.getRequestQueue().getRequestRepository().checkRanges();

            logger.debug("CAEngine: checking certificate serial number ranges");
            ca.getCertificateRepository().checkRanges();
        }
    }

    /**
     * Returns the main/host CA.
     */
    public CertificateAuthority getCA() {
        return (CertificateAuthority) getSubsystem(CertificateAuthority.ID);
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
