//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import com.netscape.certsrv.base.PKIException;

/**
 * Maps PKIException to JAX-RS Response for Quarkus deployment.
 */
@Provider
public class PKIExceptionMapperQuarkus implements ExceptionMapper<PKIException> {

    @Override
    public Response toResponse(PKIException exception) {
        return Response.status(exception.getCode())
                .entity("{\"ClassName\":\"" + exception.getClass().getSimpleName()
                        + "\",\"Message\":\"" + exception.getMessage() + "\"}")
                .type("application/json")
                .build();
    }
}
