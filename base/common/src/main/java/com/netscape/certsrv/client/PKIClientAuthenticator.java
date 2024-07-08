//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.core.MultivaluedMap;

import org.mozilla.jss.netscape.security.util.Utils;

public class PKIClientAuthenticator implements ClientRequestFilter {

    ClientConfig config;

    public PKIClientAuthenticator(ClientConfig config) {
        this.config = config;
    }

    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {

        String credentials = config.getUsername() + ":" + config.getPassword();
        byte[] bytes = credentials.getBytes(StandardCharsets.UTF_8);
        String authorization = "Basic " + Utils.base64encodeSingleLine(bytes);

        MultivaluedMap<String, Object> headers = requestContext.getHeaders();
        headers.add("Authorization", authorization);
    }
}
