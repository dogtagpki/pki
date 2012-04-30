package com.netscape.cms.servlet.cert;

import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import com.netscape.cms.servlet.cert.model.CertDataInfos;
import com.netscape.cms.servlet.cert.model.CertSearchData;

@Path("/certs")
public interface CertsResource {
    public static final int DEFAULT_MAXTIME = 10;
    public static final int DEFAULT_MAXRESULTS = 100;

    @GET
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    public CertDataInfos listCerts(
                                 @QueryParam("status") String status,
                                 @DefaultValue(""+DEFAULT_MAXRESULTS) @QueryParam("maxResults") int maxResults,
                                 @DefaultValue(""+DEFAULT_MAXTIME) @QueryParam("maxTime") int maxTime);

    @POST
    @Path("search")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public CertDataInfos searchCerts(
                                CertSearchData data,
                                @DefaultValue(""+DEFAULT_MAXRESULTS) @QueryParam("maxResults") int maxResults,
                                @DefaultValue(""+DEFAULT_MAXTIME) @QueryParam("maxTime") int maxTime);

}
