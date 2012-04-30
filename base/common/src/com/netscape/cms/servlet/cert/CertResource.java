package com.netscape.cms.servlet.cert;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cms.servlet.cert.model.CertificateData;

@Path("/cert")
public interface CertResource {

    @GET
    @Path("{id}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    public CertificateData retrieveCert(@PathParam("id") CertId id);

}
