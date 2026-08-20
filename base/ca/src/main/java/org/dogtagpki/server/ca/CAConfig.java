//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.dogtagpki.legacy.ca.CAPolicyConfig;

import com.netscape.ca.CRLConfig;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.connector.ConnectorsConfig;
import com.netscape.certsrv.security.SigningUnitConfig;
import com.netscape.cms.servlet.cert.scep.SCEPConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.cmscore.ldap.PublishingConfig;

/**
 * Provides ca.* parameters.
 */
public class CAConfig extends ConfigStore {

    public CAConfig(ConfigStorage storage) {
        super(storage);
    }

    public CAConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public boolean getOCSPUseCache() throws EBaseException {
        return getBoolean("ocspUseCache", false);
    }

    public void setOCSPUseCache(boolean ocspUseCache) {
        putBoolean("ocspUseCache", ocspUseCache);
    }

    public String getOCSPUseCacheIssuingPointId() throws EBaseException {
        return getString("ocspUseCacheIssuingPointId", CertificateAuthority.PROP_MASTER_CRL);
    }

    public void setOCSPUseCacheIssuingPointId(String ocspUseCacheIssuingPointId) {
        putString("ocspUseCacheIssuingPointId", ocspUseCacheIssuingPointId);
    }

    public boolean getOSPUseCacheCheckDeltaCache() throws EBaseException {
        return getBoolean("ocspUseCacheCheckDeltaCache", false);
    }

    public void setOCSPUseCacheCheckDeltaCache(boolean ocspUseCacheCheckDeltaCache) {
        putBoolean("ocspUseCacheCheckDeltaCache", ocspUseCacheCheckDeltaCache);
    }

    public boolean getOCSPUseCacheIncludeExpiredCerts() throws EBaseException {
        return getBoolean("ocspUseCacheIncludeExpiredCerts", false);
    }

    public void setOCSPUseCacheIncludeExpiredCerts(boolean ocspUseCacheIncludeExpiredCerts) {
        putBoolean("ocspUseCacheIncludeExpiredCerts", ocspUseCacheIncludeExpiredCerts);
    }

    /**
     * Returns ca.publish.* parameters.
     */
    public PublishingConfig getPublishingConfig() {
        return getSubStore("publish", PublishingConfig.class);
    }

    /**
     * Returns ca.signing.* parameters.
     */
    public SigningUnitConfig getSigningUnitConfig() {
        return getSubStore("signing", SigningUnitConfig.class);
    }

    /**
     * Returns ca.ocsp_signing.* parameters.
     */
    public SigningUnitConfig getOCSPSigningUnitConfig() {
        return getSubStore("ocsp_signing", SigningUnitConfig.class);
    }

    /**
     * Returns ca.crl_signing.* parameters.
     */
    public SigningUnitConfig getCRLSigningUnitConfig() {
        return getSubStore("crl_signing", SigningUnitConfig.class);
    }

    /**
     * Returns ca.crl.* parameters.
     */
    public CRLConfig getCRLConfig() {
        return getSubStore("crl", CRLConfig.class);
    }

    /**
     * Returns ca.connector.* parameters.
     */
    public ConnectorsConfig getConnectorsConfig() {
        return getSubStore("connector", ConnectorsConfig.class);
    }

    /**
     * Returns ca.Policy.* parameters.
     */
    public CAPolicyConfig getPolicyConfig() {
        return getSubStore(CertificateAuthority.PROP_POLICY, CAPolicyConfig.class);
    }

    /**
     * Returns ca.scep.* parameters.
     */
    public SCEPConfig getSCEPConfig() {
        return getSubStore("scep", SCEPConfig.class);
    }

    /**
     * Returns the comma-separated list of digest algorithms from CS.cfg 
     * ca.ocspRejectAlgorithms or ocsp.rejectAlgorithms to reject in OCSP requests.
     * If not configured or empty, all algorithms are accepted.
     *
     * Example: "SHA-1,MD5,MD2"
     *
     * @return the list of algorithm names to reject, or empty string if not set
     * @throws EBaseException if configuration cannot be read
     */
    public String getOCSPRejectAlgorithms() throws EBaseException {
        return getString("ocspRejectAlgorithms", "");
    }

    /**
     * Sets the list of digest algorithms to reject in OCSP requests.
     *
     * @param algorithms comma-separated list of algorithm names to reject from CS.cfg file
     */
    public void setOCSPRejectAlgorithms(String algorithms) {
        if (algorithms == null || algorithms.isEmpty()) {
            remove("ocspRejectAlgorithms");
        } else {
            putString("ocspRejectAlgorithms", algorithms);
        }
    }

    /**
     * Checks if a digest algorithm should be rejected in OCSP requests.
     *
     * @param algorithm the algorithm name to check from CS.cfg file (e.g., "SHA-1", "MD5")
     * @return true if the algorithm should be rejected, false otherwise
     * @throws EBaseException if configuration cannot be read
     */
    public boolean isOCSPAlgorithmRejected(String algorithm) throws EBaseException {
        String rejectList = getOCSPRejectAlgorithms();
        if (rejectList == null || rejectList.isEmpty()) {
            return false;
        }
        for (String rejected : rejectList.split(",")) {
            if (rejected.trim().equalsIgnoreCase(algorithm)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the list of executable paths allowed for use by
     * ExternalProcessConstraint, from
     * ca.externalProcessConstraint.allowedExecutables in CS.cfg.
     *
     * Each entry must be an absolute path.  If the parameter is
     * absent or empty, an empty list is returned (no executables
     * are allowed).
     *
     * @return list of allowed absolute paths (may be empty, never null)
     * @throws EBaseException if a value is empty or not an absolute path
     */
    public List<String> getExternalProcessConstraintAllowedExecutables() throws EBaseException {
        String value = getString("externalProcessConstraint.allowedExecutables", "");
        if (value == null || value.trim().isEmpty()) {
            return new ArrayList<>();
        }
        List<String> result = Arrays.asList(value.split(","));
        for (String path : result) {
            if (path.isEmpty()) {
                throw new EBaseException(
                    "ca.externalProcessConstraint.allowedExecutables:"
                    + " empty value in list");
            }
            if (!path.startsWith("/")) {
                throw new EBaseException(
                    "ca.externalProcessConstraint.allowedExecutables:"
                    + " not an absolute path: " + path);
            }
        }
        return result;
    }

}
