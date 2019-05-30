package org.dogtagpki.server.rest;

import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
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

        // The exception Data can onlybe serialised as XML or JSON,
        // so coerce the response content type to one of these.
        // Default to XML, but consider the Accept header.
        MediaType contentType = MediaType.APPLICATION_XML_TYPE;
        for (MediaType acceptType : headers.getAcceptableMediaTypes()) {
            if (acceptType.isCompatible(MediaType.APPLICATION_XML_TYPE)) {
                contentType = MediaType.APPLICATION_XML_TYPE;
                break;
            }
            if (acceptType.isCompatible(MediaType.APPLICATION_JSON_TYPE)) {
                contentType = MediaType.APPLICATION_JSON_TYPE;
                break;
            }
        }

        return Response
                .status(exception.getCode())
                .entity(exception.getData())
                .type(contentType)
                .build();
    }
}
