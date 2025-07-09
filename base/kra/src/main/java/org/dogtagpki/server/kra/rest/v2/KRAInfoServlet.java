//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.rest.v2;

import java.io.PrintWriter;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.dogtagpki.common.KRAInfo;
import org.mozilla.jss.netscape.security.util.WrappingParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "kraInfo",
        urlPatterns = "/v2/info")
public class KRAInfoServlet extends KRAServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(KRAInfoServlet.class);
    private static final String ENCRYPT_MECHANISM = "encrypt";
    private static final String KEYWRAP_MECHANISM = "keywrap";

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void getInfo(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KRAInfoService.getInfo(): session: {}", session.getId());
        boolean encryptArchival =  config.getBoolean("kra.allowEncDecrypt.archival", false);

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

        PrintWriter out = response.getWriter();
        out.println(info.toJSON());
    }
}
