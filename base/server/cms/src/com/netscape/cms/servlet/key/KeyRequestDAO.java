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
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import javax.ws.rs.Path;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.crypto.KeyGenAlgorithm;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyArchivalRequest;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.key.KeyNotFoundException;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.key.KeyRequestInfoCollection;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.key.KeyRequestResponse;
import com.netscape.certsrv.key.KeyResource;
import com.netscape.certsrv.key.SymKeyGenerationRequest;
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

    public static final Map<String, KeyGenAlgorithm> KEYGEN_ALGORITHMS;

    static {
        KEYGEN_ALGORITHMS = new HashMap<String, KeyGenAlgorithm>();
        KEYGEN_ALGORITHMS.put(KeyRequestResource.DES_ALGORITHM, KeyGenAlgorithm.DES);
        KEYGEN_ALGORITHMS.put(KeyRequestResource.DESEDE_ALGORITHM, KeyGenAlgorithm.DESede);
        KEYGEN_ALGORITHMS.put(KeyRequestResource.DES3_ALGORITHM, KeyGenAlgorithm.DES3);
        KEYGEN_ALGORITHMS.put(KeyRequestResource.RC2_ALGORITHM, KeyGenAlgorithm.RC2);
        KEYGEN_ALGORITHMS.put(KeyRequestResource.RC4_ALGORITHM, KeyGenAlgorithm.RC4);
        KEYGEN_ALGORITHMS.put(KeyRequestResource.AES_ALGORITHM, KeyGenAlgorithm.AES);
    }

    private static String REQUEST_ARCHIVE_OPTIONS = IEnrollProfile.REQUEST_ARCHIVE_OPTIONS;
    private static String REQUEST_SECURITY_DATA = IEnrollProfile.REQUEST_SECURITY_DATA;
    private static String REQUEST_SESSION_KEY = IEnrollProfile.REQUEST_SESSION_KEY;
    private static String REQUEST_ALGORITHM_OID = IEnrollProfile.REQUEST_ALGORITHM_OID;
    private static String REQUEST_ALGORITHM_PARAMS = IEnrollProfile.REQUEST_ALGORITHM_PARAMS;

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
    public KeyRequestInfoCollection listRequests(String filter, RequestId start, int pageSize, int maxResults, int maxTime,
            UriInfo uriInfo) throws EBaseException {

        KeyRequestInfoCollection ret = new KeyRequestInfoCollection();

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
    public KeyRequestResponse submitRequest(KeyArchivalRequest data, UriInfo uriInfo) throws EBaseException {
        String clientKeyId = data.getClientKeyId();
        String wrappedSecurityData = data.getWrappedPrivateData();
        String transWrappedSessionKey = data.getTransWrappedSessionKey();
        String algorithmOID = data.getAlgorithmOID();
        String symkeyParams = data.getSymmetricAlgorithmParams();
        String pkiArchiveOptions = data.getPKIArchiveOptions();
        String dataType = data.getDataType();
        String keyAlgorithm = data.getKeyAlgorithm();
        int keyStrength = dataType.equals(KeyRequestResource.SYMMETRIC_KEY_TYPE) ?
                data.getKeySize(): 0;

        boolean keyExists = doesKeyExist(clientKeyId, "active");

        if (keyExists == true) {
            throw new BadRequestException("Can not archive already active existing key!");
        }

        IRequest request = queue.newRequest(IRequest.SECURITY_DATA_ENROLLMENT_REQUEST);

        if (pkiArchiveOptions != null) {
            request.setExtData(REQUEST_ARCHIVE_OPTIONS, pkiArchiveOptions);
        } else {
            request.setExtData(REQUEST_SECURITY_DATA, wrappedSecurityData);
            request.setExtData(REQUEST_SESSION_KEY, transWrappedSessionKey);
            request.setExtData(REQUEST_ALGORITHM_PARAMS, symkeyParams);
            request.setExtData(REQUEST_ALGORITHM_OID, algorithmOID);
        }
        request.setExtData(IRequest.SECURITY_DATA_CLIENT_KEY_ID, clientKeyId);
        request.setExtData(IRequest.SECURITY_DATA_TYPE, dataType);
        request.setExtData(IRequest.SECURITY_DATA_STRENGTH,
                (keyStrength > 0) ? Integer.toString(keyStrength) : Integer.toString(0));

        if (keyAlgorithm != null) {
            request.setExtData(IRequest.SECURITY_DATA_ALGORITHM, keyAlgorithm);
        }

        queue.processRequest(request);

        queue.markAsServiced(request);

        return createKeyRequestResponse(request, uriInfo);
    }

    /**
     * Submits a key recovery request.
     *
     * @param data
     * @return info on the recovery request created
     * @throws EBaseException
     */
    public KeyRequestResponse submitRequest(KeyRecoveryRequest data, UriInfo uriInfo) throws EBaseException {
        // set data using request.setExtData(field, data)

        String wrappedSessionKeyStr = data.getTransWrappedSessionKey();
        String wrappedPassPhraseStr = data.getSessionWrappedPassphrase();
        String nonceDataStr = data.getNonceData();

        IRequest request = queue.newRequest(IRequest.SECURITY_DATA_RECOVERY_REQUEST);

        KeyId keyId = data.getKeyId();
        try {
            repo.readKeyRecord(keyId.toBigInteger());
        } catch (EDBRecordNotFoundException e) {
            throw new KeyNotFoundException(keyId);
        }

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

        return createKeyRequestResponse(request, uriInfo);
    }

    public KeyRequestResponse submitRequest(SymKeyGenerationRequest data, UriInfo uriInfo) throws EBaseException {
        String clientKeyId = data.getClientKeyId();
        String algName = data.getKeyAlgorithm();
        Integer keySize = data.getKeySize();
        List<String> usages = data.getUsages();
        String transWrappedSessionKey = data.getTransWrappedSessionKey();

        if (StringUtils.isBlank(clientKeyId)) {
            throw new BadRequestException("Invalid key generation request. Missing client ID");
        }

        boolean keyExists = doesKeyExist(clientKeyId, "active");
        if (keyExists == true) {
            throw new BadRequestException("Can not archive already active existing key!");
        }

        if (keySize == null) {
            keySize = new Integer(0);
        }

        if (StringUtils.isBlank(algName)) {
            if (keySize.intValue() != 0) {
                throw new BadRequestException(
                        "Invalid request.  Must specify key algorithm if size is specified");
            }
            algName = KeyRequestResource.AES_ALGORITHM;
            keySize = new Integer(128);
        }

        KeyGenAlgorithm alg = KEYGEN_ALGORITHMS.get(algName);
        if (alg == null) {
            throw new BadRequestException("Invalid Algorithm");
        }

        if (!alg.isValidStrength(keySize.intValue())) {
            throw new BadRequestException("Invalid key size for this algorithm");
        }

        IRequest request = queue.newRequest(IRequest.SYMKEY_GENERATION_REQUEST);

        request.setExtData(IRequest.SYMKEY_GEN_ALGORITHM, algName);
        request.setExtData(IRequest.SYMKEY_GEN_SIZE, keySize);
        request.setExtData(IRequest.SECURITY_DATA_STRENGTH, keySize);
        request.setExtData(IRequest.SECURITY_DATA_ALGORITHM, algName);

        request.setExtData(IRequest.SYMKEY_GEN_USAGES, StringUtils.join(usages, ","));
        request.setExtData(IRequest.SECURITY_DATA_CLIENT_KEY_ID, clientKeyId);

        if (transWrappedSessionKey != null) {
            request.setExtData(IRequest.SYMKEY_TRANS_WRAPPED_SESSION_KEY,
                    transWrappedSessionKey);
        }

        queue.processRequest(request);
        queue.markAsServiced(request);

        return createKeyRequestResponse(request, uriInfo);
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

    private KeyData createKeyData(IRequest request, UriInfo uriInfo) {
        // TODO - to be implemented when we enable one-shot generation and recovery
        // with retrieval
        return null;
    }

    private KeyRequestResponse createKeyRequestResponse(IRequest request, UriInfo uriInfo) {
        KeyRequestResponse response = new KeyRequestResponse();
        response.setRequestInfo(createKeyRequestInfo(request, uriInfo));
        response.setKeyData(createKeyData(request, uriInfo));
        return response;
    }

    @Override
    public KeyRequestInfo createCMSRequestInfo(IRequest request, UriInfo uriInfo) {
        return createKeyRequestInfo(request, uriInfo);
    }

    public KeyRequestResponse createCMSRequestResponse(IRequest request, UriInfo uriInfo) {
        return createKeyRequestResponse(request, uriInfo);
    }

    //We only care if the key exists or not
    private boolean doesKeyExist(String clientKeyId, String keyStatus) {
        String filter = null;
        if (keyStatus == null) {
            filter = "(" + IKeyRecord.ATTR_CLIENT_ID + "=" + clientKeyId + ")";
        } else {
            filter = "(&(" + IKeyRecord.ATTR_CLIENT_ID + "=" + clientKeyId + ")"
                     + "(" + IKeyRecord.ATTR_STATUS + "=" + keyStatus + "))";
        }
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
