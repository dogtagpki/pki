//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.est;

import java.util.HashMap;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.Provider;

/** Fix the formatting of the response Content-Type header.
 *
 * The value of the response Content-Type header is derived from the
 * "@Produces" annotation on the service method.  For example:
 *
 *    @Produces("application/pkcs7-mime; smime-type=certs-only")
 *
 * The JAX-RS machinery then converts this into a value of type
 * javax.ws.rs.core.MediaType, and it is set as such in the
 * response headers (a MultivaluedMap<String, Object>).
 *
 * When serialising the Response, header values are stringified via
 * types that implement the  RuntimeDelegate.HeaderDelegate<T>
 * interface, where T is the real type of the header value Object
 * (e.g. MediaType).  The HeaderDelegate implementations are
 * supplied by the JAX-RS implementation.  In our case that's
 * Resteasy, and the class in question:
 *
 *     public class MediaTypeHeaderDelegate
 *         implements RuntimeDelegate.HeaderDelegate<MediaType>;
 *
 * The toString(MediaType type) method provided by this class
 * prints the media type WITHOUT a space between the subtype
 * and the parameters.  In the example from the @Produces above,
 * it results in the header value:
 *
 *    application/pkcs7-mime;smime-type=certs-only
 *
 * This is a legal production in the HTTP grammar.  From the RFCs
 * 7230 and 7231:
 *
 *    media-type = type "/" subtype *( OWS ";" OWS parameter )
 *    OWS = *( SP / HTAB )
 *
 * However, at least one EST client is unable to process this
 * value.  libest expects a SPACE after the ';'.  From
 * src/est/est_client_http.c:
 *
 *    ...
 *    } else if (!strncmp(ct, "application/pkcs7-mime; smime-type=certs-only", 45)) {
 *    ...
 *
 * The string libest expects is also a valid production.  But it is
 * not the one being sent from Tomcat/Resteasy.  As a consequence,
 * the enrollment operation fails.
 *
 * To make our EST implementation compatible with libest, we need to
 * override how the MediaType gets stringified.  I was unable to
 * find a way in the JAX-RS to override the HeaderDelegate.  But we
 * can solve it in a case-by-case way via this response filter.
 *
 * At the time response filters are applied, the Content-Type header
 * value is an object of type MediaType.  If the value is equal
 * (including parameters) to a value whose serialisation we need
 * to precisely control, we replace it with the exact String
 * required.  The String value will be used in the response "as is".
 * These substitutions are stored in a Map generated from the list
 * of all verbatim target headers.
 *
 * If it emerges that different stringifications of the same
 * MediaType value are required for different client
 * implementations, we could inspect the request User-Agent header
 * to further refine the behaviour.  We could, for example, create a
 * Map for each User-Agent that requires header substitutions, or
 * change the key of the map to the User-Agent×MediaType pair.
 */
@Provider
public class ReformatContentTypeResponseFilter
        implements ContainerResponseFilter {

    private static org.slf4j.Logger logger =
        org.slf4j.LoggerFactory.getLogger(ReformatContentTypeResponseFilter.class);

    // Additional "verbatim" header values go here
    private static String[] verbatim = {
        "application/pkcs7-mime; smime-type=certs-only"
    };

    private static HashMap<MediaType, String> substitutions = new HashMap<>();

    static {
        for (String s : verbatim) {
            substitutions.put(MediaType.valueOf(s), s);
        }
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        logger.debug("ReformatContentTypeResponseFilter: inspecting response");
        Object v = responseContext.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE);
        if (v != null && v instanceof MediaType && substitutions.containsKey(v)) {
            responseContext.getHeaders().putSingle(HttpHeaders.CONTENT_TYPE, substitutions.get(v));
        }
    }
}
