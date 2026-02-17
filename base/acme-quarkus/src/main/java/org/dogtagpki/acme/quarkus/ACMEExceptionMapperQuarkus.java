//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import org.dogtagpki.acme.ACMEException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Maps ACMEException to proper HTTP responses with RFC 7807 problem detail bodies.
 */
@Provider
public class ACMEExceptionMapperQuarkus implements ExceptionMapper<ACMEException> {

    private static final Logger logger = LoggerFactory.getLogger(ACMEExceptionMapperQuarkus.class);

    @Override
    public Response toResponse(ACMEException exception) {
        int statusCode = exception.getCode();

        logger.info("ACME error: status={}, detail={}", statusCode, exception.getMessage());

        // ACMEException provides serialized error via getSerializedError()
        try {
            String serializedError = exception.getSerializedError();
            if (serializedError != null) {
                return Response.status(statusCode)
                        .type(exception.getSerializedFormat())
                        .entity(serializedError)
                        .build();
            }
        } catch (Exception e) {
            logger.error("Failed to serialize ACME error", e);
        }

        return Response.status(statusCode)
                .type(MediaType.TEXT_PLAIN)
                .entity(exception.getMessage())
                .build();
    }
}
