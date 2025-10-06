package org.dogtagpki.server.rest.v1;

import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import com.netscape.certsrv.base.PKIException;

@Provider
public class PKIExceptionMapper implements ExceptionMapper<PKIException> {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIExceptionMapper.class);

    @Context
    private HttpHeaders headers;

    @Override
    public Response toResponse(PKIException exception) {

        logger.info("PKIExceptionMapper: Returning " + exception.getClass().getSimpleName());

        // The exception Data can only be serialised as XML or JSON,
        // so coerce the response content type to one of these.
        // Default to JSON, but consider the Accept header.
        MediaType contentType = MediaType.APPLICATION_JSON_TYPE;
        for (MediaType acceptType : headers.getAcceptableMediaTypes()) {
            if (acceptType.isCompatible(MediaType.APPLICATION_JSON_TYPE)) {
                contentType = MediaType.APPLICATION_JSON_TYPE;
                break;
            }
            if (acceptType.isCompatible(MediaType.APPLICATION_XML_TYPE)) {
                contentType = MediaType.APPLICATION_XML_TYPE;
                break;
            }
        }

        Object entity;
        try {
            if (MediaType.APPLICATION_XML_TYPE.isCompatible(contentType)) {
                entity = exception.getData().toXML();
                logger.info("PKIExceptionMapper: XML exception:\n" + entity);

            } else if (MediaType.APPLICATION_JSON_TYPE.isCompatible(contentType)) {
                entity = exception.getData();
                // TODO: Replace with custom JSON mapping
                // entity = exception.getData().toJSON();
                // logger.info("PKIExceptionMapper: JSON exception:\n" + entity);

            } else {
                logger.error("PKIExceptionMapper: Unsupported exception format: " + contentType);
                throw new Exception("Unsupported exception format: " + contentType);
            }

        } catch (Exception e) {
            logger.error("PKIExceptionMapper: Unable to map exception: " + e.getMessage(), e);
            throw new RuntimeException("Unable to map exception: " + e.getMessage(), e);
        }

        return Response
                .status(exception.getCode())
                .entity(entity)
                .type(contentType)
                .build();
    }
}
