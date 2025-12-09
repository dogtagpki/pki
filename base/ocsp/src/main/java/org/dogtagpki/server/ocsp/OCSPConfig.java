//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.security.SigningUnitConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides ocsp.* parameters.
 */
public class OCSPConfig extends ConfigStore {

    public OCSPConfig(ConfigStorage storage) {
        super(storage);
    }

    public OCSPConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns ocsp.signing.* parameters.
     */
    public SigningUnitConfig getSigningUnitConfig() {
        return getSubStore("signing", SigningUnitConfig.class);
    }

    /**
     * Returns whether to reject OCSP requests using deprecated digest algorithms
     * (MD2, MD5, SHA-1) for FIPS 140-3 compliance.
     *
     * @return true if deprecated algorithms should be rejected, false otherwise (default: false)
     * @throws EBaseException if configuration cannot be read
     */
    public boolean getRejectDeprecatedAlgorithms() throws EBaseException {
        return getBoolean("rejectDeprecatedAlgorithms", false);
    }

    /**
     * Sets whether to reject OCSP requests using deprecated digest algorithms.
     *
     * @param reject true to reject deprecated algorithms, false to allow
     */
    public void setRejectDeprecatedAlgorithms(boolean reject) {
        putBoolean("rejectDeprecatedAlgorithms", reject);
    }

    /**
     * Returns the signing algorithm to use for OCSP responses.
     * If not configured, returns null to indicate the default algorithm
     * from the OCSP signing unit should be used.
     *
     * Example values: SHA256withRSA, SHA384withRSA, SHA512withRSA,
     *                 SHA256withEC, SHA384withEC, SHA512withEC
     *
     * @return the configured signing algorithm, or null if not set
     * @throws EBaseException if configuration cannot be read
     */
    public String getResponseSigningAlgorithm() throws EBaseException {
        return getString("responseSigningAlgorithm", null);
    }

    /**
     * Sets the signing algorithm to use for OCSP responses.
     *
     * @param algorithm the signing algorithm (e.g., SHA256withRSA), or null to use default
     */
    public void setResponseSigningAlgorithm(String algorithm) {
        if (algorithm == null) {
            remove("responseSigningAlgorithm");
        } else {
            putString("responseSigningAlgorithm", algorithm);
        }
    }
}
