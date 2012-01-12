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

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.IRequestVirtualList;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.base.model.Link;

/**
 * @author alee
 *
 */
public class KeyRequestDAO {
    private IRequestQueue queue;
    
    private String[] vlvFilters = {
            "(requeststate=*)", "(requesttype=enrollment)",
            "(requesttype=recovery)", "(requeststate=canceled)",
            "(&(requeststate=canceled)(requesttype=enrollment))",
            "(&(requeststate=canceled)(requesttype=recovery))", 
            "(requeststate=rejected)", 
            "(&(requeststate=rejected)(requesttype=enrollment))",
            "(&(requeststate=rejected)(requesttype=recovery))",
            "(requeststate=complete)",
            "(&(requeststate=complete)(requesttype=enrollment))",
            "(&(requeststate=complete)(requesttype=recovery))"
    };
    
    public KeyRequestDAO() {
        IKeyRecoveryAuthority kra = null;
        kra = ( IKeyRecoveryAuthority ) CMS.getSubsystem( "kra" );
        queue = kra.getRequestQueue();
    }

    /**
     * Finds list of requests matching the specified search filter.  
     * 
     * If the filter corresponds to a VLV search, then that search is executed and the pageSize 
     * and start parameters are used.  Otherwise, the maxResults and maxTime parameters are
     * used in the regularly indexed search.
     * 
     * @param filter - ldap search filter
     * @param start - start position for VLV search
     * @param pageSize - page size for VLV search
     * @param maxResults - max results to be returned in normal search
     * @param maxTime - max time for normal search
     * @param uriInfo - uri context of request
     * @return collection of key request info
     * @throws EBaseException
     */
    public KeyRequestInfos listRequests(String filter, int start, int pageSize, int maxResults, int maxTime, 
            UriInfo uriInfo) throws EBaseException {
        List <KeyRequestInfo> list = new ArrayList<KeyRequestInfo>();
        List <Link> links = new ArrayList<Link>();
        int totalSize = 0;
        int current = 0;
        
        if (isVLVSearch(filter)) {
            RequestId id = new RequestId(Integer.toString(start));
            IRequestVirtualList vlvlist = queue.getPagedRequestsByFilter(id, false, filter, 
                                                                         pageSize +1 , "requestId");
            totalSize = vlvlist.getSize();
            current = vlvlist.getCurrentIndex();
            
            int numRecords = (totalSize > (current + pageSize)) ? pageSize :
                totalSize - current;
            
            for (int i=0; i < numRecords; i++) {
                IRequest request = vlvlist.getElementAt(i);
                list.add(createKeyRequestInfo(request, uriInfo));
            }
        } else {
            // The non-vlv requests are indexed, but are not paginated.
            // We should think about whether they should be, or if we need to
            // limit the number of results returned.
            IRequestList requests = queue.listRequestsByFilter(filter, maxResults, maxTime);
            while (requests.hasMoreElements()) {
                RequestId rid = (RequestId) requests.nextElement();
                IRequest request = queue.findRequest(rid);
                if (request != null) {
                    list.add(createKeyRequestInfo(request, uriInfo));
                }
            }
        }
        
        // builder for vlv links
        MultivaluedMap<String, String> params = uriInfo.getQueryParameters();
        UriBuilder builder = uriInfo.getAbsolutePathBuilder();
        if (params.containsKey("requestState")) {
            builder.queryParam("requestState", params.getFirst("requestState"));
        }
        if (params.containsKey("requestType")) {
            builder.queryParam("requestType", params.getFirst("requestType"));
        }
        builder.queryParam("start", "{start}");
        builder.queryParam("pageSize", "{pageSize}");
        
        // next link
        if (totalSize > current + pageSize) {
            int next = current + pageSize + 1;
            URI nextUri = builder.clone().build(next,pageSize);
            Link nextLink = new Link("next", nextUri.toString(), "application/xml");
            links.add(nextLink);
        }
        
        // previous link
        if (current >0) {
            int previous = current - pageSize;
            URI previousUri = builder.clone().build(previous,pageSize);
            Link previousLink = new Link("previous", previousUri.toString(), "application/xml");
            links.add(previousLink);
        }
        
        KeyRequestInfos ret = new KeyRequestInfos();
        ret.setRequests(list);
        ret.setLinks(links);
        return ret;
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
    
    private boolean isVLVSearch(String filter) {
        for (int i=0; i < vlvFilters.length; i++) {
            if (vlvFilters[i].equalsIgnoreCase(filter)) {
                return true;
            }
        }
        return false;
    }
}
