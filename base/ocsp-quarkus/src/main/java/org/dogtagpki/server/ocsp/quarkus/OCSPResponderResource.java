//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URLDecoder;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.netscape.security.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.event.OCSPGenerationEvent;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.ResponseBytes;
import com.netscape.cmsutil.ocsp.ResponseData;
import com.netscape.cmsutil.ocsp.SingleResponse;
import com.netscape.cmsutil.ocsp.TBSRequest;
import com.netscape.ocsp.OCSPAuthority;

/**
 * JAX-RS resource for OCSP protocol handling (RFC 2560/6960).
 *
 * Replaces OCSPOCSPServlet which serves the /ee/ocsp endpoint.
 * Accepts binary OCSP requests via POST and base64-encoded
 * requests via GET, returning binary OCSP responses.
 */
@Path("ee/ocsp")
public class OCSPResponderResource {

    private static final Logger logger = LoggerFactory.getLogger(OCSPResponderResource.class);

    private static final String OCSP_REQUEST_CONTENT_TYPE = "application/ocsp-request";
    private static final String OCSP_RESPONSE_CONTENT_TYPE = "application/ocsp-response";
    private static final int MAX_REQUEST_SIZE = 5000;

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @Context
    UriInfo uriInfo;

    @POST
    @Consumes(OCSP_REQUEST_CONTENT_TYPE)
    @Produces(OCSP_RESPONSE_CONTENT_TYPE)
    public Response processPost(byte[] requestData) throws Exception {
        logger.info("OCSPResponderResource: Processing POST request");

        if (requestData == null || requestData.length == 0) {
            logger.error("OCSPResponderResource: Empty OCSP request");
            return Response.status(400).entity("Empty OCSP request").build();
        }

        if (requestData.length > MAX_REQUEST_SIZE) {
            logger.error("OCSPResponderResource: Request too large: {} bytes", requestData.length);
            return Response.status(400).entity("OCSP request too large").build();
        }

        return processOCSPRequest(new ByteArrayInputStream(requestData));
    }

    @GET
    @Path("{encodedRequest: .+}")
    @Produces(OCSP_RESPONSE_CONTENT_TYPE)
    public Response processGet() throws Exception {
        logger.debug("OCSPResponderResource: Processing GET request");

        String path = uriInfo.getPath();
        // Extract the encoded OCSP request from the path after "ee/ocsp/"
        String encodedRequest = path.substring("ee/ocsp/".length());

        if (encodedRequest == null || encodedRequest.isEmpty()) {
            logger.error("OCSPResponderResource: No OCSP request in GET path");
            return Response.status(400).entity("OCSP request not provided in GET method").build();
        }

        // URL-decode the request
        String decodedRequest = URLDecoder.decode(encodedRequest, "UTF-8");

        // Base64-decode the request
        byte[] requestBytes = Utils.base64decode(decodedRequest);

        return processOCSPRequest(new ByteArrayInputStream(requestBytes));
    }

    private Response processOCSPRequest(InputStream requestStream) {
        Auditor auditor = engineQuarkus.getEngine().getAuditor();
        OCSPAuthority ocsp = engineQuarkus.getEngine().getOCSP();

        try {
            // Decode the OCSP request
            OCSPRequest.Template reqTemplate = new OCSPRequest.Template();
            OCSPRequest ocspReq = (OCSPRequest) reqTemplate.decode(requestStream);

            if (ocspReq == null) {
                logger.error("OCSPResponderResource: Empty or malformed OCSP request");
                auditor.log(OCSPGenerationEvent.createFailureEvent(null, "Empty or malformed OCSP request"));
                return Response.status(400).entity("Empty or malformed OCSP request").build();
            }

            if (logger.isDebugEnabled()) {
                TBSRequest tbsReq = ocspReq.getTBSRequest();
                logger.debug("OCSPResponderResource: OCSP Request:");
                logger.debug("OCSPResponderResource: " + Utils.base64encode(ASN1Util.encode(ocspReq), true));
                logger.debug("OCSPResponderResource: Cert status requests:");
                for (int i = 0; i < tbsReq.getRequestCount(); i++) {
                    com.netscape.cmsutil.ocsp.Request req = tbsReq.getRequestAt(i);
                    CertId certID = new CertId(req.getCertID().getSerialNumber());
                    logger.debug("OCSPResponderResource: - " + certID.toHexString());
                }
            }

            // Validate the request using OCSPAuthority
            logger.debug("OCSPResponderResource: Validating request");
            OCSPResponse response = ocsp.validate(ocspReq);

            if (response == null) {
                auditor.log(OCSPGenerationEvent.createFailureEvent(null, "Missing OCSP response"));
                logger.warn("OCSPResponderResource: Response is null");
                return Response.serverError().build();
            }

            auditor.log(OCSPGenerationEvent.createSuccessEvent(null));

            // Encode the response
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            response.encode(bos);
            byte[] respBytes = bos.toByteArray();

            if (logger.isDebugEnabled()) {
                logger.debug("OCSPResponderResource: OCSP Response Size: {}", respBytes.length);
                logger.debug("OCSPResponderResource: OCSP Response Data:");
                logger.debug("OCSPResponderResource: " + Utils.base64encode(respBytes, true));

                ResponseBytes rbytes = response.getResponseBytes();
                if (rbytes != null && rbytes.getObjectIdentifier().equals(ResponseBytes.OCSP_BASIC)) {
                    BasicOCSPResponse basicRes = (BasicOCSPResponse)
                            BasicOCSPResponse.getTemplate().decode(
                                    new ByteArrayInputStream(rbytes.getResponse().toByteArray()));
                    if (basicRes != null) {
                        ResponseData data = basicRes.getResponseData();
                        for (int i = 0; i < data.getResponseCount(); i++) {
                            SingleResponse res = data.getResponseAt(i);
                            logger.debug("OCSPResponderResource: Serial Number: {}",
                                    res.getCertID().getSerialNumber());
                            logger.debug("OCSPResponderResource: Status: {}",
                                    res.getCertStatus().getClass().getName());
                        }
                    }
                }
            }

            return Response.ok(respBytes)
                    .type(OCSP_RESPONSE_CONTENT_TYPE)
                    .build();

        } catch (Exception e) {
            logger.warn("OCSPResponderResource: Error processing OCSP request: {}", e.getMessage(), e);
            if (auditor != null) {
                auditor.log(OCSPGenerationEvent.createFailureEvent(null, e.getMessage()));
            }
            return Response.serverError().build();
        }
    }
}
