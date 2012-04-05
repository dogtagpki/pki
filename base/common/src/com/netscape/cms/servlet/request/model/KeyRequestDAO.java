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
import java.util.Hashtable;
import java.util.List;

import javax.ws.rs.Path;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.IRequestVirtualList;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.base.model.Link;
import com.netscape.cms.servlet.key.KeyResource;
import com.netscape.cms.servlet.key.model.KeyDAO;
import com.netscape.cms.servlet.key.model.KeyDataInfos;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.cms.servlet.request.KeyRequestResource;

/**
 * @author alee
 *
 */
public class KeyRequestDAO {
    private IRequestQueue queue;
    private IKeyRecoveryAuthority kra;

    private static String REQUEST_ARCHIVE_OPTIONS = IEnrollProfile.REQUEST_ARCHIVE_OPTIONS;

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

    public static final String ATTR_SERIALNO = "serialNumber";

    public KeyRequestDAO() {
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
    public KeyRequestInfos listRequests(String filter, RequestId start, int pageSize, int maxResults, int maxTime,
            UriInfo uriInfo) throws EBaseException {
        List <KeyRequestInfo> list = new ArrayList<KeyRequestInfo>();
        List <Link> links = new ArrayList<Link>();
        int totalSize = 0;
        int current = 0;

        if (isVLVSearch(filter)) {
            IRequestVirtualList vlvlist = queue.getPagedRequestsByFilter(start, false, filter,
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

            if (requests == null) {
                return null;
            }
            while (requests.hasMoreElements()) {
                RequestId rid = requests.nextElement();
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
    public KeyRequestInfo getRequest(RequestId id, UriInfo uriInfo) throws EBaseException {
        IRequest request = queue.findRequest(id);
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
        String clientId = data.getClientId();
        String wrappedSecurityData = data.getWrappedPrivateData();
        String dataType = data.getDataType();

        boolean keyExists = doesKeyExist(clientId, "active", uriInfo);

        if (keyExists == true) {
            throw new EBaseException("Can not archive already active existing key!");
        }

        IRequest request = queue.newRequest(IRequest.SECURITY_DATA_ENROLLMENT_REQUEST);

        request.setExtData(REQUEST_ARCHIVE_OPTIONS, wrappedSecurityData);
        request.setExtData(IRequest.SECURITY_DATA_CLIENT_ID, clientId);
        request.setExtData(IRequest.SECURITY_DATA_TYPE, dataType);

        queue.processRequest(request);

        queue.markAsServiced(request);

        return createKeyRequestInfo(request, uriInfo);
    }
    /**
     * Submits a key recovery request.
     * @param data
     * @return info on the recovery request created
     * @throws EBaseException
     */
    public KeyRequestInfo submitRequest(RecoveryRequestData data, UriInfo uriInfo) throws EBaseException {

        // set data using request.setExtData(field, data)

        String wrappedSessionKeyStr = data.getTransWrappedSessionKey();
        String wrappedPassPhraseStr = data.getSessionWrappedPassphrase();
        String nonceDataStr = data.getNonceData();

        IRequest request = queue.newRequest(IRequest.SECURITY_DATA_RECOVERY_REQUEST);

        KeyId keyId = data.getKeyId();

        Hashtable<String, Object> requestParams;
        requestParams = kra.createVolatileRequest(request.getRequestId());

        if(requestParams == null) {
            throw new EBaseException("Can not create Volatile params in submitRequest!");
        }

        CMS.debug("Create volatile  params for recovery request. " + requestParams);

        if (wrappedPassPhraseStr != null) {
            requestParams.put(IRequest.SECURITY_DATA_SESS_PASS_PHRASE, wrappedPassPhraseStr);
        }

        if (wrappedSessionKeyStr != null) {
            requestParams.put(IRequest.SECURITY_DATA_TRANS_SESS_KEY, wrappedSessionKeyStr);
        }

        if (nonceDataStr != null) {
            requestParams.put(IRequest.SECURITY_DATA_IV_STRING_IN, nonceDataStr);
        }

        request.setExtData(ATTR_SERIALNO, keyId.toString());

        queue.processRequest(request);

        return createKeyRequestInfo(request, uriInfo);
    }

    public void approveRequest(RequestId id) throws EBaseException {
        IRequest request = queue.findRequest(id);
        request.setRequestStatus(RequestStatus.APPROVED);
        queue.updateRequest(request);
    }

    public void rejectRequest(RequestId id) throws EBaseException {
        IRequest request = queue.findRequest(id);
        request.setRequestStatus(RequestStatus.CANCELED);
        queue.updateRequest(request);
    }

    public void cancelRequest(RequestId id) throws EBaseException {
        IRequest request = queue.findRequest(id);
        request.setRequestStatus(RequestStatus.REJECTED);
        queue.updateRequest(request);
    }

    public KeyRequestInfo createKeyRequestInfo(IRequest request, UriInfo uriInfo) {
        KeyRequestInfo ret = new KeyRequestInfo();

        ret.setRequestType(request.getRequestType());
        ret.setRequestStatus(request.getRequestStatus().toString());

        Path keyRequestPath = KeyRequestResource.class.getAnnotation(Path.class);
        RequestId rid = request.getRequestId();

        UriBuilder reqBuilder = uriInfo.getBaseUriBuilder();
        reqBuilder.path(keyRequestPath.value() + "/" + rid);
        ret.setRequestURL(reqBuilder.build().toString());

        Path keyPath = KeyResource.class.getAnnotation(Path.class);
        String kid = request.getExtDataInString("keyrecord");

        UriBuilder keyBuilder = uriInfo.getBaseUriBuilder();
        keyBuilder.path(keyPath.value() + "/" + kid);
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

    //We only care if the key exists or not
    private boolean doesKeyExist(String clientId, String keyStatus, UriInfo uriInfo) {
        boolean ret = false;
        String state = "active";

        KeyDAO  keys = new KeyDAO();

        KeyDataInfos existingKeys;
        String filter = "(&(" + IRequest.SECURITY_DATA_CLIENT_ID + "=" + clientId + ")"
                    + "(" + IRequest.SECURITY_DATA_STATUS + "=" + state + "))";
        try {
            existingKeys =  keys.listKeys(filter, 1, 10,  uriInfo);

            if(existingKeys != null && existingKeys.getKeyInfos().size() > 0) {
                ret = true;
            }
        } catch (EBaseException e) {
            ret= false;
        }

        return ret;
    }
}
