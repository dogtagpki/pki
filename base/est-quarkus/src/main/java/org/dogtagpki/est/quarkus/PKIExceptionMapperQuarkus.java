package org.dogtagpki.est.quarkus;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;

/**
 * Exception mapper for PKI exceptions in Quarkus.
 *
 * Maps PKI exceptions to appropriate HTTP response codes.
 * Simplified version for PoC.
 *
 * @author Claude Code (Quarkus PoC)
 */
@Provider
public class PKIExceptionMapperQuarkus implements ExceptionMapper<PKIException> {

    private static final Logger logger = LoggerFactory.getLogger(PKIExceptionMapperQuarkus.class);

    @Override
    public Response toResponse(PKIException exception) {
        logger.error("PKI Exception: {}", exception.getMessage(), exception);

        Response.Status status;
        String message = exception.getMessage();

        if (exception instanceof BadRequestException) {
            status = Response.Status.BAD_REQUEST;
        } else if (exception instanceof UnauthorizedException) {
            status = Response.Status.UNAUTHORIZED;
        } else if (exception instanceof ForbiddenException) {
            status = Response.Status.FORBIDDEN;
        } else if (exception instanceof ResourceNotFoundException) {
            status = Response.Status.NOT_FOUND;
        } else {
            status = Response.Status.INTERNAL_SERVER_ERROR;
        }

        return Response.status(status)
                       .entity(message)
                       .type("text/plain")
                       .build();
    }
}
