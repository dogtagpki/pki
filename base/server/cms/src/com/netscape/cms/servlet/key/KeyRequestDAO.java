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

import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.util.Arrays;
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
import org.mozilla.jss.crypto.KeyPairAlgorithm;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.EAuthzUnknownRealm;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.AsymKeyGenerationRequest;
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
import com.netscape.certsrv.kra.IKeyService;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.request.CMSRequestInfo;
import com.netscape.certsrv.request.CMSRequestInfos;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.request.CMSRequestDAO;
import com.netscape.cmsutil.util.Utils;

import netscape.security.x509.X509CertImpl;

/**
 * @author alee
 *
 */
public class KeyRequestDAO extends CMSRequestDAO {

    public static final Map<String, KeyGenAlgorithm> SYMKEY_GEN_ALGORITHMS;
    public static final Map<String, KeyPairAlgorithm> ASYMKEY_GEN_ALGORITHMS;

    static {
        SYMKEY_GEN_ALGORITHMS = new HashMap<String, KeyGenAlgorithm>();
        SYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.DES_ALGORITHM, KeyGenAlgorithm.DES);
        SYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.DESEDE_ALGORITHM, KeyGenAlgorithm.DESede);
        SYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.DES3_ALGORITHM, KeyGenAlgorithm.DES3);
        SYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.RC2_ALGORITHM, KeyGenAlgorithm.RC2);
        SYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.RC4_ALGORITHM, KeyGenAlgorithm.RC4);
        SYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.AES_ALGORITHM, KeyGenAlgorithm.AES);

        ASYMKEY_GEN_ALGORITHMS = new HashMap<String, KeyPairAlgorithm>();
        ASYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.RSA_ALGORITHM, KeyPairAlgorithm.RSA);
        ASYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.DSA_ALGORITHM, KeyPairAlgorithm.DSA);
    }

    private static String REQUEST_ARCHIVE_OPTIONS = IEnrollProfile.REQUEST_ARCHIVE_OPTIONS;
    private static String REQUEST_SECURITY_DATA = IEnrollProfile.REQUEST_SECURITY_DATA;
    private static String REQUEST_SESSION_KEY = IEnrollProfile.REQUEST_SESSION_KEY;
    private static String REQUEST_ALGORITHM_OID = IEnrollProfile.REQUEST_ALGORITHM_OID;
    private static String REQUEST_ALGORITHM_PARAMS = IEnrollProfile.REQUEST_ALGORITHM_PARAMS;

    public static final String ATTR_SERIALNO = "serialNumber";

    private IKeyRepository repo;
    private IKeyRecoveryAuthority kra;
    private IKeyService service;

    public KeyRequestDAO() {
        super("kra");
        kra = ( IKeyRecoveryAuthority ) CMS.getSubsystem( "kra" );
        repo = kra.getKeyRepository();
        service = (IKeyService) kra;
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
     * @param authToken - auth token
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
     * @param uriInfo
     * @param authToken - authentication token for this request
     * @return info for specific request
     * @throws EBaseException
     */
    public KeyRequestInfo getRequest(RequestId id, UriInfo uriInfo, IAuthToken authToken) throws EBaseException {
        IRequest request = queue.findRequest(id);
        if (request == null) {
            return null;
        }

        authz.checkRealm(request.getRealm(), authToken, request.getExtDataInString(IRequest.ATTR_REQUEST_OWNER),
                "certServer.kra.request", "read");

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
    public KeyRequestResponse submitRequest(KeyArchivalRequest data, UriInfo uriInfo, String owner)
            throws EBaseException {
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
        String realm = data.getRealm();

        boolean keyExists = doesKeyExist(clientKeyId, "active");

        if (keyExists == true) {
            throw new BadRequestException("Can not archive already active existing key!");
        }

        IRequest request = queue.newRequest(IRequest.SECURITY_DATA_ENROLLMENT_REQUEST, kra.isEphemeral(realm));

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

        request.setExtData(IRequest.ATTR_REQUEST_OWNER, owner);

        if (realm != null) {
            request.setRealm(realm);
        }

        if (!kra.isEphemeral(realm)) {
            queue.processRequest(request);
            queue.markAsServiced(request);
        } else {
            kra.processSynchronousRequest(request);
        }

        return createKeyRequestResponse(request, uriInfo);
    }

    public IRequest createRecoveryRequest(KeyRecoveryRequest data, UriInfo uriInfo, String requestor,
            IAuthToken authToken, boolean ephemeral) throws EBaseException{
        if (data == null) {
            throw new BadRequestException("Invalid request.");
        }

        /*if (data.getCertificate() == null &&
            data.getTransWrappedSessionKey() == null &&
            data.getSessionWrappedPassphrase() != null) {
            throw new BadRequestException("No wrapped session key.");
        }*/

        if (requestor == null) {
            throw new UnauthorizedException("Recovery must be initiated by an agent");
        }

        KeyId keyId = data.getKeyId();
        IKeyRecord rec = null;
        try {
            rec = repo.readKeyRecord(keyId.toBigInteger());
        } catch (EDBRecordNotFoundException e) {
            throw new KeyNotFoundException(keyId, "key not found to recover", e);
        }

        try {
            authz.checkRealm(rec.getRealm(), authToken, rec.getOwnerName(), "certServer.kra.key", "recover");
        } catch (EAuthzUnknownRealm e) {
            throw new UnauthorizedException("Invalid realm", e);
        } catch (EBaseException e) {
            throw new UnauthorizedException("Agent not authorized by realm", e);
        }

        IRequest request = queue.newRequest(IRequest.SECURITY_DATA_RECOVERY_REQUEST, ephemeral);

        if (rec.getRealm() != null) {
            request.setRealm(rec.getRealm());
        }

        request.setExtData(ATTR_SERIALNO, keyId.toString());
        request.setExtData(IRequest.ATTR_REQUEST_OWNER, requestor);
        request.setExtData(IRequest.ATTR_APPROVE_AGENTS, requestor);

        String encryptOID = data.getPaylodEncryptionOID();
        if (encryptOID != null)
            request.setExtData(IRequest.SECURITY_DATA_PL_ENCRYPTION_OID, encryptOID);

        return request;
    }

    public void setTransientData(KeyRecoveryRequest data, IRequest request) throws EBaseException {

        Hashtable<String, Object> requestParams = getTransientData(request);

        String wrappedSessionKeyStr = data.getTransWrappedSessionKey();
        String wrappedPassPhraseStr = data.getSessionWrappedPassphrase();
        String nonceDataStr = data.getNonceData();
        String encryptOID = data.getPaylodEncryptionOID();

        if (wrappedPassPhraseStr != null) {
            requestParams.put(IRequest.SECURITY_DATA_SESS_PASS_PHRASE, wrappedPassPhraseStr);
        }

        if (wrappedSessionKeyStr != null) {
            requestParams.put(IRequest.SECURITY_DATA_TRANS_SESS_KEY, wrappedSessionKeyStr);
        }

        if (nonceDataStr != null) {
            requestParams.put(IRequest.SECURITY_DATA_IV_STRING_IN, nonceDataStr);
        }

        if (encryptOID != null) {
            requestParams.put(IRequest.SECURITY_DATA_PL_ENCRYPTION_OID, encryptOID);
        }
    }

    public Hashtable<String, Object> getTransientData(IRequest request) throws EBaseException {
        Hashtable<String, Object> requestParams;
        requestParams = ((IKeyRecoveryAuthority) authority).getVolatileRequest(request.getRequestId());
        if (requestParams == null) {
            requestParams = ((IKeyRecoveryAuthority) authority).createVolatileRequest(request.getRequestId());
            if (requestParams == null) {
                throw new EBaseException("Can not create Volatile params in createRecoveryRequest!");
            }
        }
        return requestParams;
    }

    /**
     * Submits a key recovery request.
     *
     * @param data
     * @param uriInfo
     * @param requestor
     * @param authToken
     * @return info on the recovery request created
     * @throws EBaseException
     */
    public KeyRequestResponse submitRequest(KeyRecoveryRequest data, UriInfo uriInfo, String requestor,
            IAuthToken authToken)
            throws EBaseException {
        IRequest request = createRecoveryRequest(data, uriInfo, requestor, authToken, false);
        setTransientData(data, request);
        queue.processRequest(request);

        return createKeyRequestResponse(request, uriInfo);
    }

    public KeyRequestResponse submitAsyncKeyRecoveryRequest(KeyRecoveryRequest data, UriInfo uriInfo,
            String requestor, IAuthToken authToken) throws EBaseException {
        if (data == null) {
            throw new BadRequestException("Invalid request.");
        }

        KeyId keyId = data.getKeyId();
        IKeyRecord rec = null;
        try {
            rec = repo.readKeyRecord(keyId.toBigInteger());
        } catch (EDBRecordNotFoundException e) {
            throw new KeyNotFoundException(keyId, "key not found to recover", e);
        }

        String realm = rec.getRealm();
        try {
            authz.checkRealm(realm, authToken, rec.getOwnerName(), "certServer.kra.key", "recover");
        } catch (EAuthzUnknownRealm e) {
            throw new UnauthorizedException("Invalid realm", e);
        } catch (EBaseException e) {
            throw new UnauthorizedException("Agent not authorized by realm", e);
        }

        String b64Certificate = data.getCertificate();
        byte[] certData = Utils.base64decode(b64Certificate);
        String requestId = null;
        try {
            requestId = service.initAsyncKeyRecovery(new BigInteger(keyId.toString()),
                    new X509CertImpl(certData), requestor, realm);
        } catch (EBaseException | CertificateException e) {
            e.printStackTrace();
            throw new PKIException(e.toString(), e);
        }
        IRequest request = null;
        try {
            request = queue.findRequest(new RequestId(requestId));
        } catch (EBaseException e) {
        }
        return createCMSRequestResponse(request, uriInfo);
    }

    public KeyRequestResponse submitRequest(SymKeyGenerationRequest data, UriInfo uriInfo, String owner)
            throws EBaseException {
        String clientKeyId = data.getClientKeyId();
        String algName = data.getKeyAlgorithm();
        Integer keySize = data.getKeySize();
        List<String> usages = data.getUsages();
        String transWrappedSessionKey = data.getTransWrappedSessionKey();
        String realm = data.getRealm();

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

        KeyGenAlgorithm alg = SYMKEY_GEN_ALGORITHMS.get(algName);
        if (alg == null) {
            throw new BadRequestException("Invalid Algorithm");
        }

        if (!alg.isValidStrength(keySize.intValue())) {
            throw new BadRequestException("Invalid key size for this algorithm");
        }

        IRequest request = queue.newRequest(IRequest.SYMKEY_GENERATION_REQUEST);

        request.setExtData(IRequest.KEY_GEN_ALGORITHM, algName);
        request.setExtData(IRequest.KEY_GEN_SIZE, keySize);
        request.setExtData(IRequest.SECURITY_DATA_STRENGTH, keySize);
        request.setExtData(IRequest.SECURITY_DATA_ALGORITHM, algName);

        request.setExtData(IRequest.KEY_GEN_USAGES, StringUtils.join(usages, ","));
        request.setExtData(IRequest.SECURITY_DATA_CLIENT_KEY_ID, clientKeyId);
        request.setExtData(IRequest.ATTR_REQUEST_OWNER, owner);

        if (transWrappedSessionKey != null) {
            request.setExtData(IRequest.KEY_GEN_TRANS_WRAPPED_SESSION_KEY,
                    transWrappedSessionKey);
        }

        if (realm != null) {
            request.setRealm(realm);
        }

        queue.processRequest(request);
        queue.markAsServiced(request);

        return createKeyRequestResponse(request, uriInfo);
    }

    public KeyRequestResponse submitRequest(AsymKeyGenerationRequest data, UriInfo uriInfo, String owner)
            throws EBaseException {
        String clientKeyId = data.getClientKeyId();
        String algName = data.getKeyAlgorithm();
        Integer keySize = data.getKeySize();
        List<String> usages = data.getUsages();
        String transWrappedSessionKey = data.getTransWrappedSessionKey();
        String realm = data.getRealm();

        if (StringUtils.isBlank(clientKeyId)) {
            throw new BadRequestException("Invalid key generation request. Missing client ID");
        }

        boolean keyExists = doesKeyExist(clientKeyId, "active");
        if (keyExists == true) {
            throw new BadRequestException("Cannot archive already active existing key!");
        }

        if (StringUtils.isBlank(algName)) {
            if (keySize.intValue() != 0) {
                throw new BadRequestException(
                        "Invalid request.  Must specify key algorithm if size is specified");
            }
        }

        KeyPairAlgorithm alg = ASYMKEY_GEN_ALGORITHMS.get(algName);
        if (alg == null) {
            throw new BadRequestException("Unsupported algorithm specified.");
        }

        if (keySize == null) {
            if (algName.equalsIgnoreCase(KeyRequestResource.RSA_ALGORITHM)
                    || algName.equalsIgnoreCase(KeyRequestResource.DSA_ALGORITHM)) {
                throw new BadRequestException("Key size must be specified.");
            }
        } else {
            //Validate key size
            if (algName.equalsIgnoreCase(KeyRequestResource.RSA_ALGORITHM)) {
                int size = Integer.valueOf(keySize);
                int minSize = Integer.valueOf(CMS.getConfigStore().getInteger("keys.rsa.min.size", 256));
                int maxSize = Integer.valueOf(CMS.getConfigStore().getInteger("keys.rsa.max.size", 8192));
                if (minSize > maxSize) {
                    throw new PKIException("Incorrect size parameters stored in config file.");
                }
                if (size < minSize || size > maxSize) {
                    throw new BadRequestException("Key size out of supported range - " + minSize + " - " + maxSize);
                }
                //JSS supports key sizes that are of the form 256 + (16*n), where n = 0-1008, for RSA
                if (((size - 256) % 16) != 0) {
                    throw new BadRequestException("Invalid key size specified.");
                }
            } else if (algName.equalsIgnoreCase(KeyRequestResource.DSA_ALGORITHM)) {
                // Without the PQGParams, JSS can create DSA keys of size 512, 768, 1024 only.
                String[] sizes = CMS.getConfigStore().getString("keys.dsa.list", "512,768,1024").split(",");
                if (!Arrays.asList(sizes).contains(String.valueOf(keySize))) {
                    throw new BadRequestException("Invalid key size specified.");
                }
            }
        }

        IRequest request = queue.newRequest(IRequest.ASYMKEY_GENERATION_REQUEST);

        request.setExtData(IRequest.KEY_GEN_ALGORITHM, algName);
        request.setExtData(IRequest.KEY_GEN_SIZE, keySize);
        request.setExtData(IRequest.SECURITY_DATA_STRENGTH, keySize);
        request.setExtData(IRequest.SECURITY_DATA_ALGORITHM, algName);

        request.setExtData(IRequest.KEY_GEN_USAGES, StringUtils.join(usages, ","));
        request.setExtData(IRequest.SECURITY_DATA_CLIENT_KEY_ID, clientKeyId);
        request.setExtData(IRequest.ATTR_REQUEST_OWNER, owner);

        if (realm != null) {
            request.setRealm(realm);
        }

        if (transWrappedSessionKey != null) {
            request.setExtData(IRequest.KEY_GEN_TRANS_WRAPPED_SESSION_KEY,
                    transWrappedSessionKey);
        }

        queue.processRequest(request);
        queue.markAsServiced(request);

        return createKeyRequestResponse(request, uriInfo);
    }

    public void approveRequest(RequestId id, String requestor, IAuthToken authToken)
            throws EBaseException {
        IRequest request = queue.findRequest(id);
        authz.checkRealm(request.getRealm(), authToken,
                request.getExtDataInString(IRequest.ATTR_REQUEST_OWNER),
                "certServer.kra.requests", "execute");

        service.addAgentAsyncKeyRecovery(id.toString(), requestor);
    }

    public void rejectRequest(RequestId id, IAuthToken authToken) throws EBaseException {
        IRequest request = queue.findRequest(id);
        String realm = request.getRealm();
        authz.checkRealm(realm, authToken,
                request.getExtDataInString(IRequest.ATTR_REQUEST_OWNER),
                "certServer.kra.requests", "execute");
        request.setRequestStatus(RequestStatus.REJECTED);
        queue.updateRequest(request);
    }

    public void cancelRequest(RequestId id, IAuthToken authToken) throws EBaseException {
        IRequest request = queue.findRequest(id);
        String realm = request.getRealm();
        authz.checkRealm(realm, authToken,
                request.getExtDataInString(IRequest.ATTR_REQUEST_OWNER),
                "certServer.kra.requests", "execute");
        request.setRequestStatus(RequestStatus.CANCELED);
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
        String keyID = request.getExtDataInString("keyrecord");

        if (keyID != null) {
            // set key URL only if key ID is available
            UriBuilder keyBuilder = uriInfo.getBaseUriBuilder();
            keyBuilder.path(keyPath.value() + "/" + keyID);
            ret.setKeyURL(keyBuilder.build().toString());
        }

        if (request.getRealm()!= null) {
            ret.setRealm(request.getRealm());
        }

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
