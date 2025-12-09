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
     * Returns the comma-separated list of digest algorithms to reject in OCSP requests.
     * If not configured or empty, all algorithms are accepted.
     * In the OCSP CS.cfg the param ocsp.rejectAlgorithms=SHA-1,MD5,MD2 is added
     *
     * @return the list of algorithm names to reject, or empty string if not set
     * @throws EBaseException if configuration cannot be read
     */
    public String getRejectAlgorithms() throws EBaseException {
        return getString("rejectAlgorithms", "");
    }

    /**
     * Sets the list of digest algorithms to reject in OCSP requests.
     *
     * @param algorithms comma-separated list of algorithm names to reject
     */
    public void setRejectAlgorithms(String algorithms) {
        if (algorithms == null || algorithms.isEmpty()) {
            remove("rejectAlgorithms");
        } else {
            putString("rejectAlgorithms", algorithms);
        }
    }

    /**
     * Checks if a digest algorithm should be rejected in OCSP requests.
     *
     * @param algorithm the algorithm name to check (e.g., "SHA-1", "MD5")
     * @return true if the algorithm should be rejected, false otherwise
     * @throws EBaseException if configuration cannot be read
     */
    public boolean isAlgorithmRejected(String algorithm) throws EBaseException {
        String rejectList = getRejectAlgorithms();
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

}
