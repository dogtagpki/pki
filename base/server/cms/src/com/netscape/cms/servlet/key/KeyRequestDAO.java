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

import java.util.Collection;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

import javax.ws.rs.Path;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyArchivalRequest;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.key.KeyRequestInfos;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.key.KeyResource;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.request.CMSRequestInfo;
import com.netscape.certsrv.request.CMSRequestInfos;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.request.CMSRequestDAO;

/**
 * @author alee
 *
 */
public class KeyRequestDAO extends CMSRequestDAO {

    private static String REQUEST_ARCHIVE_OPTIONS = IEnrollProfile.REQUEST_ARCHIVE_OPTIONS;
    public static final String ATTR_SERIALNO = "serialNumber";

    private IKeyRepository repo;
    private IKeyRecoveryAuthority kra;

    public KeyRequestDAO() {
        super("kra");
        kra = ( IKeyRecoveryAuthority ) CMS.getSubsystem( "kra" );
        repo = kra.getKeyRepository();
    }

    /**
     * Finds list of requests matching the specified search filter.
     *
     * If the filter corresponds to a VLV search, then that search is executed and the pageSize
     * and start parameters are used. Otherwise, the maxResults and maxTime parameters are
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
    @SuppressWarnings("unchecked")
    public KeyRequestInfos listRequests(String filter, RequestId start, int pageSize, int maxResults, int maxTime,
            UriInfo uriInfo) throws EBaseException {

        KeyRequestInfos ret = new KeyRequestInfos();

        CMSRequestInfos cmsInfos = listCMSRequests(filter, start, pageSize, maxResults, maxTime, uriInfo);

        ret.setTotal(cmsInfos.getTotal());

        Collection<? extends CMSRequestInfo> cmsList = cmsInfos.getEntries();

        // We absolutely know 100% that this list is a list
        // of KeyRequestInfo objects. This is because the method
        // createCMSRequestInfo. Is the only one adding to it

        List<KeyRequestInfo> list = (List<KeyRequestInfo>) cmsList;
        ret.setEntries(list);

        ret.setLinks(cmsInfos.getLinks());

        return ret;
    }

    /**
     * Gets info for a specific request
     *
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
     *
     * @param data
     * @return info for the request submitted.
     * @throws EBaseException
     */
    public KeyRequestInfo submitRequest(KeyArchivalRequest data, UriInfo uriInfo) throws EBaseException {
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
     *
     * @param data
     * @return info on the recovery request created
     * @throws EBaseException
     */
    public KeyRequestInfo submitRequest(KeyRecoveryRequest data, UriInfo uriInfo) throws EBaseException {
        // set data using request.setExtData(field, data)

        String wrappedSessionKeyStr = data.getTransWrappedSessionKey();
        String wrappedPassPhraseStr = data.getSessionWrappedPassphrase();
        String nonceDataStr = data.getNonceData();

        IRequest request = queue.newRequest(IRequest.SECURITY_DATA_RECOVERY_REQUEST);

        KeyId keyId = data.getKeyId();

        Hashtable<String, Object> requestParams;

        requestParams = ((IKeyRecoveryAuthority) authority).createVolatileRequest(request.getRequestId());

        if (requestParams == null) {
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

    private KeyRequestInfo createKeyRequestInfo(IRequest request, UriInfo uriInfo) {
        KeyRequestInfo ret = new KeyRequestInfo();

        ret.setRequestType(request.getRequestType());
        ret.setRequestStatus(request.getRequestStatus());

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

    @Override
    public KeyRequestInfo createCMSRequestInfo(IRequest request, UriInfo uriInfo) {
        return createKeyRequestInfo(request, uriInfo);
    }

    //We only care if the key exists or not
    private boolean doesKeyExist(String clientId, String keyStatus, UriInfo uriInfo) {
        String state = "active";
        String filter = "(&(" + IRequest.SECURITY_DATA_CLIENT_ID + "=" + clientId + ")"
                + "(" + IRequest.SECURITY_DATA_STATUS + "=" + state + "))";
        try {
            Enumeration<IKeyRecord> existingKeys = null;

            existingKeys = repo.searchKeys(filter, 1, 10);
            if (existingKeys != null && existingKeys.hasMoreElements()) {
                return true;
            }
        } catch (EBaseException e) {
            return false;
        }

        return false;
    }
}
