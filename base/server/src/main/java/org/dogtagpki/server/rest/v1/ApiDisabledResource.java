package org.dogtagpki.server.rest.v1;

import javax.ws.rs.GET;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.DELETE;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.base.PATCH;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Catch-all resource that returns a clean error message when v1 API is disabled.
 * This is registered as the only resource when API status is disabled.
 */
@Path("/")
public class ApiDisabledResource {

    public static final Logger logger = LoggerFactory.getLogger(ApiDisabledResource.class);
    
    private static final ObjectMapper mapper = new ObjectMapper();

    private Response createErrorResponse() {
        try {
            ObjectNode error = mapper.createObjectNode();
            error.put("error", "REST API v1 have been disabled");
            error.put("message", "The REST API v1 have been disabled in this PKI instance. Please use the API v2 instead.");
            error.put("documentation", "https://github.com/dogtagpki/pki/wiki/REST-API-v2");

            return Response
                .status(Response.Status.NOT_FOUND) // 404 Not Found
                .entity(error.toString())
                .type("application/json")
                .header("Deprecation", "true")
                .header("Link", "<https://github.com/dogtagpki/pki/wiki/REST-API-v2>; rel=\"alternate\"")
                .build();
        } catch (Exception e) {
            logger.warn("Problem handling disabled v1 API: " + e.getMessage(), e);
            return Response
                .status(Response.Status.NOT_FOUND)
                .entity("{\"error\":\"REST API v1 have been disabled\",\"message\":\"Please use API v2\"}")
                .type("application/json")
                .build();
        }
    }

    @GET
    @Path("{path:.*}")
    public Response handleGet(@PathParam("path") String path) {
        return createErrorResponse();
    }

    @POST
    @Path("{path:.*}")
    public Response handlePost(@PathParam("path") String path) {
        return createErrorResponse();
    }

    @PUT
    @Path("{path:.*}")
    public Response handlePut(@PathParam("path") String path) {
        return createErrorResponse();
    }

    @DELETE
    @Path("{path:.*}")
    public Response handleDelete(@PathParam("path") String path) {
        return createErrorResponse();
    }

    @PATCH
    @Path("{path:.*}")
    public Response handlePatch(@PathParam("path") String path) {
        return createErrorResponse();
    }

    @OPTIONS
    @Path("{path:.*}")
    public Response handleOptions(@PathParam("path") String path) {
        return createErrorResponse();
    }
}
