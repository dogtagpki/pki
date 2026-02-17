//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.common.KRAInfo;
import org.dogtagpki.server.kra.KRAEngine;
import org.dogtagpki.server.kra.KRAEngineConfig;
import org.mozilla.jss.netscape.security.util.WrappingParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * JAX-RS resource for KRA info endpoint.
 * Replaces KRAInfoServlet.
 */
@Path("v2/info")
public class KRAInfoResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAInfoResource.class);
    private static final String ENCRYPT_MECHANISM = "encrypt";
    private static final String KEYWRAP_MECHANISM = "keywrap";

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getInfo() throws Exception {
        logger.debug("KRAInfoResource.getInfo()");

        KRAEngine engine = engineQuarkus.getEngine();
        KRAEngineConfig config = engine.getConfig();
        KeyRecoveryAuthority kra = (KeyRecoveryAuthority) engine.getSubsystem(KeyRecoveryAuthority.ID);
        IStorageKeyUnit storageUnit = kra.getStorageKeyUnit();

        boolean encryptArchival = config.getBoolean("kra.allowEncDecrypt.archival", false);

        KRAInfo info = new KRAInfo();
        String encryptArchivalMechanism = encryptArchival ?
                ENCRYPT_MECHANISM : KEYWRAP_MECHANISM;
        info.setArchivalMechanism(encryptArchivalMechanism);

        String encryptRecovery = config.getBoolean("kra.allowEncDecrypt.recovery", false) ?
                ENCRYPT_MECHANISM : KEYWRAP_MECHANISM;
        info.setRecoveryMechanism(encryptRecovery);

        String encryptAlgorithms;
        String wrappingParameters;
        try {
            WrappingParams params = storageUnit.getWrappingParams(encryptArchival);
            encryptAlgorithms = params.getPayloadEncryptionAlgorithm().toString();
            wrappingParameters = params.getPayloadWrapAlgorithm().toString();
        } catch (Exception e) {
            // return something that should always work
            encryptAlgorithms = "AES/CBC/Padding";
            wrappingParameters = "AES/CBC/Padding";
        }
        info.setEncryptAlgorithm(encryptAlgorithms);
        info.setWrapAlgorithm(wrappingParameters);

        String rsaWrap = config.getUseOAEPKeyWrap() ?
                "RSA_OAEP" : "RSA";
        info.setRsaPublicKeyWrapAlgorithm(rsaWrap);

        return Response.ok(info.toJSON()).build();
    }
}
