//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import com.netscape.certsrv.base.PKIException;

@Provider
public class PKIExceptionMapperQuarkus implements ExceptionMapper<PKIException> {

    @Override
    public Response toResponse(PKIException exception) {
        int code = exception.getCode();
        MediaType contentType = MediaType.APPLICATION_JSON_TYPE;

        return Response.status(code)
                .entity(exception.getSerializedError(contentType))
                .type(exception.getSerializedFormat(contentType))
                .build();
    }
}
