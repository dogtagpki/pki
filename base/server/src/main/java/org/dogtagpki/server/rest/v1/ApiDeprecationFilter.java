// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2025 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.rest.v1;

import java.io.IOException;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.ext.Provider;

/**
 * JAX-RS response filter that adds standard deprecation headers to all v1 API responses
 * when the API status is set to "deprecated".
 *
 * Implements:
 * - Deprecation header (IETF draft-dalal-deprecation-header)
 * - Link header pointing to v2 API documentation (RFC 8288)
 */
@Provider
public class ApiDeprecationFilter implements ContainerResponseFilter {

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext)
            throws IOException {
        // Add Deprecation header as per IETF draft
        responseContext.getHeaders().add("Deprecation", "true");

        // Add Link header pointing to replacement API (RFC 8288)
        responseContext.getHeaders().add("Link", "<https://github.com/dogtagpki/pki/wiki/REST-API-v2>; rel=\"alternate\"");
    }
}
