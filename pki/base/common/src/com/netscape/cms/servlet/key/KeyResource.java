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

package com.netscape.cms.servlet.key;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import com.netscape.cms.servlet.key.model.KeyDAO;
import com.netscape.cms.servlet.key.model.KeyData;
import com.netscape.cms.servlet.request.model.KeyRequestDAO;
import com.netscape.cms.servlet.request.model.KeyRequestInfo;
import com.netscape.cms.servlet.request.model.RecoveryRequestData;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.base.EBaseException;
/**
 * @author alee
 * 
 */
@Path("/key")
public class KeyResource {
    
    @Context
    UriInfo uriInfo;
    
    /**
     * Used to retrieve a key
     * @param data
     * @return
     */
    @POST
    @Path("retrieve")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public KeyData retrieveKey(RecoveryRequestData data) {
        // auth and authz
        String keyId = validateRequest(data);
        KeyDAO dao = new KeyDAO();
        KeyData keyData;
        try {
            keyData = dao.getKey(keyId, data);
        } catch (EBaseException e) {
            // log error
            e.printStackTrace();
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
        if (keyData == null) {
            // no key record
            throw new WebApplicationException(Response.Status.GONE);
        }
        return keyData;
    }
    
    // retrieval - used to test integration with a browser
    @POST
    @Path("retrieve")
    @Produces(MediaType.TEXT_XML)
    public KeyData retrieveKey(MultivaluedMap<String, String> form) {
        RecoveryRequestData data = new RecoveryRequestData(form);
        return retrieveKey(data);
    }
    
    private String validateRequest(RecoveryRequestData data) {
        // confirm that at least one wrapping method exists
        if ((data.getTransWrappedSessionKey() == null) && (data.getTransWrappedSessionKey() == null)) {
            // log error
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
        
        // confirm request exists
        String reqId = data.getRequestId();
        if (reqId == null) {
            // log error
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
        KeyRequestDAO reqDAO = new KeyRequestDAO();
        KeyRequestInfo reqInfo;
        try {
            reqInfo = reqDAO.getRequest(reqId, uriInfo);
        } catch (EBaseException e1) {
            // failed to get request
            e1.printStackTrace();
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
        if (reqInfo == null) {
            // request not found
            throw new WebApplicationException(Response.Status.GONE);
        }
        
        //confirm request is of the right type
        String type = reqInfo.getRequestType();
        if (!type.equals(IRequest.SECURITY_DATA_RECOVERY_REQUEST)) {
            // log error
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
        
        //confirm that agent is originator of request, else throw 401 
        //  TO-DO
        
        // confirm request is in approved state
        String status = reqInfo.getRequestStatus();
        if (!status.equals(RequestStatus.APPROVED.toString())) {
            // log error
            throw new WebApplicationException(Response.Status.UNAUTHORIZED);
        }
        
        String keyURL = reqInfo.getKeyURL();
        return keyURL.substring(keyURL.lastIndexOf("/")); 
    }

}
