package org.dogtagpki.est.quarkus;

import java.util.Arrays;
import java.util.List;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.ext.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filter bad Accept header values for Quarkus.
 *
 * Some EST clients send requests with Accept: text/plain.
 * This filter handles those requests by removing invalid Accept headers.
 *
 * Migrated from javax.ws.rs to jakarta.ws.rs.
 *
 * @author Fraser Tweedale (original)
 * @author Claude Code (Quarkus migration)
 */
@Provider
@PreMatching
public class HandleBadAcceptHeaderRequestFilterQuarkus
        implements ContainerRequestFilter {

    private static final Logger logger =
        LoggerFactory.getLogger(HandleBadAcceptHeaderRequestFilterQuarkus.class);

    private static final List<MediaType> RESPONSE_TYPES = Arrays.asList(
        // /cacerts, /simpleenroll, /simplereenroll
        MediaType.valueOf("application/pkcs7-mime"),

        // /serverkeygen
        MediaType.valueOf("multipart/mixed"),

        // /csrattrs
        MediaType.valueOf("application/csrattrs")
    );

    @Override
    public void filter(ContainerRequestContext requestContext) {
        logger.debug("HandleBadAcceptHeaderRequestFilter: inspecting request");
        List<MediaType> acceptTypes = requestContext.getAcceptableMediaTypes();
        MediaType match = resolveFormat(acceptTypes, RESPONSE_TYPES);

        // if no match, delete the Accept header
        if (match == null) {
            logger.info("HandleBadAcceptHeaderRequestFilter: no matching Accept header; removing it and proceeding");
            requestContext.getHeaders().remove(HttpHeaders.ACCEPT);
        }
    }

    /**
     * Resolve format from acceptable media types.
     * Simplified version of PKIService.resolveFormat for PoC.
     */
    private MediaType resolveFormat(List<MediaType> acceptTypes, List<MediaType> supportedTypes) {
        for (MediaType acceptType : acceptTypes) {
            for (MediaType supportedType : supportedTypes) {
                if (acceptType.isCompatible(supportedType)) {
                    return supportedType;
                }
            }
        }
        return null;
    }
}
