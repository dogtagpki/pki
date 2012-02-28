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

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.base.CMSResourceService;
import com.netscape.cms.servlet.request.model.ArchivalRequestData;
import com.netscape.cms.servlet.request.model.KeyRequestDAO;
import com.netscape.cms.servlet.request.model.KeyRequestInfo;
import com.netscape.cms.servlet.request.model.RecoveryRequestData;
 
/**
 * @author alee
 * 
 */
public class KeyRequestResourceService extends CMSResourceService implements KeyRequestResource {

    @Context
    UriInfo uriInfo;
    
    /**
     * Used to retrieve key request info for a specific request
     */
    public KeyRequestInfo getRequestInfo(RequestId id) {
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
    public KeyRequestInfo archiveKey(MultivaluedMap<String, String> form) {
        ArchivalRequestData data = new ArchivalRequestData(form);
        return archiveKey(data);
    }

    public KeyRequestInfo archiveKey(ArchivalRequestData data) {
        // auth and authz
        // Catch this before internal server processing has to deal with it

        if (data == null || data.getClientId() == null
                || data.getWrappedPrivateData() == null
                || data.getDataType() == null) {
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }

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
    public KeyRequestInfo recoverKey(MultivaluedMap<String, String> form) {
        RecoveryRequestData data = new RecoveryRequestData(form);
        return recoverKey(data);
    }

    public KeyRequestInfo recoverKey(RecoveryRequestData data) {
        // auth and authz

        //Check for entirely illegal data combination here
        //Catch this before the internal server processing has to deal with it
        //If data has been provided, we need at least the wrapped session key,
        //or the command is invalid.
        if (data == null || (data.getTransWrappedSessionKey() == null
                && data.getSessionWrappedPassphrase() != null)) {
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
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
    
    public void approveRequest(RequestId id) {
        if (id == null) {
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
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
    
    public void rejectRequest(RequestId id) {
        if (id == null) {
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
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
         
    public void cancelRequest(RequestId id) {
        if (id == null) {
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
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
