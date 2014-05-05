package org.dogtagpki.server.rest;

import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import com.netscape.certsrv.base.PKIException;
import com.netscape.cms.servlet.base.PKIService;

@Provider
public class PKIExceptionMapper implements ExceptionMapper<PKIException> {

    @Context
    private HttpHeaders headers;

    public Response toResponse(PKIException exception) {
        // convert PKIException into HTTP response
        return Response
                .status(exception.getCode())
                .entity(exception.getData())
                .type(PKIService.getResponseFormat(headers))
                .build();
    }
}
