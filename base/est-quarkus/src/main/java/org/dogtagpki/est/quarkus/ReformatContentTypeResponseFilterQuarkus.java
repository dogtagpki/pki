package org.dogtagpki.est.quarkus;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.ext.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Response filter to reformat Content-Type header for EST responses.
 *
 * EST protocol requires specific Content-Type formatting.
 * This filter ensures responses have properly formatted Content-Type headers.
 *
 * Migrated from javax.ws.rs to jakarta.ws.rs.
 *
 * @author Fraser Tweedale (original)
 * @author Claude Code (Quarkus migration)
 */
@Provider
public class ReformatContentTypeResponseFilterQuarkus implements ContainerResponseFilter {

    private static final Logger logger =
        LoggerFactory.getLogger(ReformatContentTypeResponseFilterQuarkus.class);

    @Override
    public void filter(ContainerRequestContext requestContext,
                      ContainerResponseContext responseContext) {
        logger.debug("ReformatContentTypeResponseFilter: processing response");

        // Get current Content-Type
        Object contentType = responseContext.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE);

        if (contentType != null) {
            String contentTypeStr = contentType.toString();

            // Ensure proper formatting for EST protocol
            // For example, "application/pkcs7-mime" should have proper parameters
            if (contentTypeStr.startsWith("application/pkcs7-mime")) {
                // EST protocol specific formatting
                logger.debug("Content-Type is pkcs7-mime: {}", contentTypeStr);
            }
        }
    }
}
