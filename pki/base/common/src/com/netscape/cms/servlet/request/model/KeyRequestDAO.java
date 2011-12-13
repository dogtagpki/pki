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
package com.netscape.cms.servlet.request.model;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;

/**
 * @author alee
 *
 */
public class KeyRequestDAO {
    private IRequestQueue queue;
    
    public KeyRequestDAO() {
        IKeyRecoveryAuthority kra = null;
        kra = ( IKeyRecoveryAuthority ) CMS.getSubsystem( "kra" );
        queue = kra.getRequestQueue();
    }

    /**
     * This will find the requests in the database matching the specified search parameters
     * Needs input validation and probably paging, maybe using the vlv functions
     * @throws EBaseException 
     */
    public List<KeyRequestInfo> listRequests(String filter, UriInfo uriInfo) throws EBaseException {
        List <KeyRequestInfo> list = new ArrayList<KeyRequestInfo>();  
        IRequestList requests = queue.listRequestsByFilter(filter);
        while (requests.hasMoreElements()) {
            RequestId rid = (RequestId) requests.nextElement();
            IRequest request;
            request = queue.findRequest(rid);
            list.add(createKeyRequestInfo(request, uriInfo));
        }
        return list;
    }
    
    /**
     * Gets info for a specific request
     * @param id
     * @return info for specific request
     * @throws EBaseException 
     */
    public KeyRequestInfo getRequest(String id, UriInfo uriInfo) throws EBaseException {
        IRequest request = queue.findRequest(new RequestId(id));
        if (request == null) {
            return null;
        }
        KeyRequestInfo info = createKeyRequestInfo(request, uriInfo);
        return info;
    }
    /**
     * Submits an archival request and processes it.
     * @param data
     * @return info for the request submitted.
     * @throws EBaseException 
     */
    public KeyRequestInfo submitRequest(ArchivalRequestData data, UriInfo uriInfo) throws EBaseException {
        IRequest request = queue.newRequest(IRequest.SECURITY_DATA_ENROLLMENT_REQUEST);
        //TODO : 
        //set data using request.setExtData(field, data)
        queue.processRequest(request);
        return createKeyRequestInfo(request, uriInfo);
    }
    /**
     * Submits a key recovery request.
     * @param data
     * @return info on the recovery request created
     * @throws EBaseException 
     */
    public KeyRequestInfo submitRequest(RecoveryRequestData data, UriInfo uriInfo) throws EBaseException { 
        IRequest request = queue.newRequest(IRequest.SECURITY_DATA_RECOVERY_REQUEST);
        // set data using request.setExtData(field, data)
        queue.processRequest(request);
        return createKeyRequestInfo(request, uriInfo);
    }

    public void approveRequest(String id) throws EBaseException {
        IRequest request = queue.findRequest(new RequestId(id));
        request.setRequestStatus(RequestStatus.APPROVED);
    }
    
    public void rejectRequest(String id) throws EBaseException {
        IRequest request = queue.findRequest(new RequestId(id));
        request.setRequestStatus(RequestStatus.CANCELED);
    }
    
    public void cancelRequest(String id) throws EBaseException {
        IRequest request = queue.findRequest(new RequestId(id));
        request.setRequestStatus(RequestStatus.REJECTED);
    }
    
    public KeyRequestInfo createKeyRequestInfo(IRequest request, UriInfo uriInfo) {
        KeyRequestInfo ret = new KeyRequestInfo();
        
        ret.setRequestType(request.getRequestType());
        ret.setRequestStatus(request.getRequestStatus().toString());
        
        String rid = request.getRequestId().toString();
        UriBuilder reqBuilder = uriInfo.getBaseUriBuilder();
        reqBuilder.path("/keyrequest/" + rid);
        ret.setRequestURL(reqBuilder.build().toString());
        
        String kid = request.getExtDataInString("keyrecord");
        UriBuilder keyBuilder = uriInfo.getBaseUriBuilder();
        keyBuilder.path("/key/" + kid);
        ret.setKeyURL(keyBuilder.build().toString());
        
        return ret;
    }
}
