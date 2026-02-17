//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.util.List;

import jakarta.inject.Inject;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.tps.rest.base.TPSCertProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.tps.cert.TPSCertCollection;
import com.netscape.certsrv.tps.cert.TPSCertData;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource for TPS certificate operations.
 * Replaces TPSCertServlet.
 */
@Path("v2/certs")
public class TPSCertResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSCertResource.class);

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity identity;

    private TPSCertProcessor createProcessor() {
        return new TPSCertProcessor(engineQuarkus.getEngine());
    }

    private List<String> getAuthorizedProfiles() {
        return TPSEngineQuarkus.getAuthorizedProfiles(identity);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findCerts(
            @QueryParam("tokenID") String tokenID,
            @QueryParam("filter") String filter,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("pageSize") @DefaultValue("20") int size) throws Exception {
        logger.debug("TPSCertResource.findCerts()");
        TPSCertCollection certs = createProcessor().findCerts(getAuthorizedProfiles(), tokenID, filter, start, size);
        return Response.ok(certs.toJSON()).build();
    }

    @GET
    @Path("{certId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCert(@PathParam("certId") String certId) throws Exception {
        logger.debug("TPSCertResource.getCert(): certId={}", certId);
        TPSCertData cert = createProcessor().getCert(certId, getAuthorizedProfiles());
        return Response.ok(cert.toJSON()).build();
    }
}
