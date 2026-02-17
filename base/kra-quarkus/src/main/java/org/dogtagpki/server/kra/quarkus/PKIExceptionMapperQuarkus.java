//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.PKIException;

/**
 * Maps PKIException to proper HTTP responses.
 */
@Provider
public class PKIExceptionMapperQuarkus implements ExceptionMapper<PKIException> {

    private static final Logger logger = LoggerFactory.getLogger(PKIExceptionMapperQuarkus.class);

    @Override
    public Response toResponse(PKIException exception) {
        int statusCode = exception.getCode();

        logger.info("PKI error: status={}, detail={}", statusCode, exception.getMessage());

        try {
            String serializedError = exception.getSerializedError();
            if (serializedError != null) {
                return Response.status(statusCode)
                        .type(exception.getSerializedFormat())
                        .entity(serializedError)
                        .build();
            }
        } catch (Exception e) {
            logger.error("Failed to serialize PKI error", e);
        }

        return Response.status(statusCode)
                .type(MediaType.TEXT_PLAIN)
                .entity(exception.getMessage())
                .build();
    }
}
