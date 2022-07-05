//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.est;

import java.util.Arrays;
import java.util.List;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.ext.Provider;

import com.netscape.cms.servlet.base.PKIService;

/** Filter bad Accept header values.
 *
 * Some EST clients are known to send requests with Accept:
 * text/plain.  The JAX-RS API is quite rigid in how it processes
 * the Accept header, although the HTTP semantics allow a server to
 * ignore the Accept header.
 *
 * So, we should make some effort to handle these requests despite
 * their dubious Accept header values.  This request filter fires
 * BEFORE resource method matching and handles request thus:
 *
 * - We do not (yet) know what resource is being requested.  We do
 *   not want to (re)implement the path matching ourselves - too
 *   complicated.
 *
 * - So, we have a list of ALL valid (success) response types of the
 *   EST protocol.  If the Accept header matches any of those, we
 *   leave it alone.
 *
 * - If the Accept header does not match any valid content-type in
 *   the EST protocol, then we delete the header and request
 *   processing continues as if the header had not been included in
 *   the request.
 *
 * - The result is that a request has an Accept header that demands
 *   a content-type that is used within the EST protocol, but which
 *   is not valid for the method and path combination, will still
 *   fail 406.  But there is only so much complexity we are willing
 *   to take on to handle dubious client behaviour.
 */
@Provider
@PreMatching
public class HandleBadAcceptHeaderRequestFilter
        implements ContainerRequestFilter {

    private static org.slf4j.Logger logger =
        org.slf4j.LoggerFactory.getLogger(HandleBadAcceptHeaderRequestFilter.class);

    private static List<MediaType> RESPONSE_TYPES = Arrays.asList(
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
        MediaType match = PKIService.resolveFormat(acceptTypes, RESPONSE_TYPES);

        // if no match, delete the Accept header
        if (match == null) {
            logger.info("HandleBadAcceptHeaderRequestFilter: no matching Accept header; removing it and proceeding");
            requestContext.getHeaders().remove(HttpHeaders.ACCEPT);
        }
    }

}
