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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.servlet.request;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.Consumes;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.request.model.ArchivalRequestData;
import com.netscape.cms.servlet.request.model.KeyRequestDAO;
import com.netscape.cms.servlet.request.model.KeyRequestInfo;
import com.netscape.cms.servlet.request.model.RecoveryRequestData;
 
/**
 * @author alee
 * 
 */
@Path("/keyrequest")
public class KeyRequestResource {
    
    @Context
    UriInfo uriInfo;
    
    /**
     * Used to retrieve key request info for a specific request
     */
    @GET
    @Path("{id}")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML  })
    public KeyRequestInfo getRequestInfo(@PathParam("id") String id) {
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestInfo info;
        try {
            info = dao.getRequest(id, uriInfo);
        } catch (EBaseException e) {
            // log error
            e.printStackTrace();
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
        if (info == null) {
            // request does not exist
            throw new WebApplicationException(Response.Status.NOT_FOUND);
        }
        return info;
    }
    
    // Archiving - used to test integration with a browser
    @POST
    @Path("archive")
    @Produces({ MediaType.TEXT_XML })
    public KeyRequestInfo archiveKey(MultivaluedMap<String, String> form) {
        ArchivalRequestData data = new ArchivalRequestData(form);
        return archiveKey(data);
    }

    @POST
    @Path("archive")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public KeyRequestInfo archiveKey(ArchivalRequestData data) {
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestInfo info;
        try {
            info = dao.submitRequest(data, uriInfo);
        } catch (EBaseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
        return info;
    }
    
    //Recovery - used to test integration with a browser
    @POST
    @Path("recover")
    @Produces({ MediaType.TEXT_XML })
    public KeyRequestInfo recoverKey(MultivaluedMap<String, String> form) {
        RecoveryRequestData data = new RecoveryRequestData(form);
        return recoverKey(data);
    }

    @POST
    @Path("recover")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public KeyRequestInfo recoverKey(RecoveryRequestData data) {
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestInfo info;
        try {
            info = dao.submitRequest(data, uriInfo);
        } catch (EBaseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
        return info;
    }
    
    @POST
    @Path("approve/{id}")
    public void approveRequest(@PathParam("id") String id) {
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        try {
            dao.approveRequest(id);
        } catch (EBaseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
    }
    
    @POST
    @Path("reject/{id}")
    public void rejectRequest(@PathParam("id") String id) {
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        try {
            dao.rejectRequest(id);
        } catch (EBaseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
    }
    
    @POST
    @Path("cancel/{id}")
    public void cancelRequest(@PathParam("id") String id) {
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        try {
            dao.cancelRequest(id);
        } catch (EBaseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
    }
}
