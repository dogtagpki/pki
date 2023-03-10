//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.security;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import com.netscape.certsrv.base.EBaseException;

public class SecureRandomFactory {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SecureRandomFactory.class);

    public static SecureRandom create(SecureRandomConfig config)
            throws EBaseException, NoSuchAlgorithmException, NoSuchProviderException {

        logger.debug("SecureRandomFactory: Creating secure random:");

        String algorithm = config.getAlgorithm();
        logger.debug("SecureRandomFactory: - algorithm: " + algorithm);

        String provider = config.getProvider();
        logger.debug("SecureRandomFactory: - provider: " + provider);

        return SecureRandom.getInstance(algorithm, provider);
    }
}
