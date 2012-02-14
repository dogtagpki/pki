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
package com.netscape.cms.servlet.key.model;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.request.model.RecoveryRequestData;

/**
 * @author alee
 *
 */
public class KeyDAO {

    private IKeyRepository repo;
    private IKeyRecoveryAuthority kra;
    private IRequestQueue queue;
    
    public KeyDAO() {
        kra = ( IKeyRecoveryAuthority ) CMS.getSubsystem( "kra" );
        repo = kra.getKeyRepository();
        queue = kra.getRequestQueue();
    }
    /**
     * Returns list of keys meeting specified search filter.
     * Currently, vlv searches are not used for keys.
     * 
     * @param filter
     * @param maxResults
     * @param maxTime
     * @param uriInfo
     * @return
     * @throws EBaseException
     */
    public KeyDataInfos listKeys(String filter, int maxResults, int maxTime, UriInfo uriInfo) 
        throws EBaseException {
        List <KeyDataInfo> list = new ArrayList<KeyDataInfo>();
        Enumeration<IKeyRecord> e = null;
        
        e = repo.searchKeys(filter, maxResults, maxTime); 
        if (e == null) {
            throw new EBaseException("search results are null");
        }
        
        while (e.hasMoreElements()) {
            IKeyRecord rec = e.nextElement();
            if (rec != null) {
                list.add(createKeyDataInfo(rec, uriInfo));
            }
        }
        
        KeyDataInfos ret = new KeyDataInfos();
        ret.setKeyInfos(list);
        
        return ret;
    }
    
    public KeyData getKey(String keyId, RecoveryRequestData data) throws EBaseException {
        KeyData keyData;
        BigInteger serial = new BigInteger(keyId);
        
        String rId = data.getRequestId();

        String transWrappedSessionKey;
        String sessionWrappedPassphrase;

        IRequest  request = queue.findRequest(new RequestId(rId));

        if (request == null) {
            return null;
        }

     // get wrapped key
        IKeyRecord rec = repo.readKeyRecord(serial);
        if (rec == null) {
            return null;  
        }

        Hashtable<String, Object> requestParams = kra.getVolatileRequest(
                request.getRequestId());

        if(requestParams == null) {
            throw new EBaseException("Can't obtain Volatile requestParams in KeyDAO.getKey!");
        }

        String sessWrappedKeyData = (String) requestParams.get(IRequest.SECURITY_DATA_SESS_WRAPPED_DATA);
        String passWrappedKeyData = (String) requestParams.get(IRequest.SECURITY_DATA_PASS_WRAPPED_DATA);
        String nonceData = (String) requestParams.get(IRequest.SECURITY_DATA_IV_STRING_OUT);

        if (sessWrappedKeyData != null || passWrappedKeyData != null) {
            //The recovery process has already placed a valid recovery
            //package, either session key wrapped or pass wrapped, into the request.
            //Request already has been processed.
            keyData = new KeyData();

        } else {
            // The request has not yet been processed, let's see if the RecoveryRequestData contains
            // the info now needed to process the recovery request.

            transWrappedSessionKey   = data.getTransWrappedSessionKey();
            sessionWrappedPassphrase = data.getSessionWrappedPassphrase();
            nonceData = data.getNonceData();

            if(transWrappedSessionKey == null) {
                 //There must be at least a transWrappedSessionKey input provided.
                 //The command AND the request have provided insufficient data, end of the line.
                 throw new EBaseException("Can't retrieve key, insufficient input data!");
            }

            if (sessionWrappedPassphrase != null) {
                requestParams.put(IRequest.SECURITY_DATA_SESS_PASS_PHRASE, sessionWrappedPassphrase);
            }

            if (transWrappedSessionKey != null) {
                requestParams.put(IRequest.SECURITY_DATA_TRANS_SESS_KEY, transWrappedSessionKey);
            }

            if (nonceData != null) {
                requestParams.put(IRequest.SECURITY_DATA_IV_STRING_IN, nonceData);
            }

            try {
                // Has to be in this state or it won't go anywhere.
                request.setRequestStatus(RequestStatus.BEGIN);
                queue.processRequest(request);
            } catch (EBaseException e) {
                kra.destroyVolatileRequest(request.getRequestId());
                throw new EBaseException(e.toString());
            }

            nonceData = null;
            keyData = new KeyData();

            sessWrappedKeyData = (String) requestParams.get(IRequest.SECURITY_DATA_SESS_WRAPPED_DATA);
            passWrappedKeyData = (String) requestParams.get(IRequest.SECURITY_DATA_PASS_WRAPPED_DATA);
            nonceData = (String) requestParams.get(IRequest.SECURITY_DATA_IV_STRING_OUT);

        }

        if (sessWrappedKeyData != null) {
            keyData.setWrappedPrivateData(sessWrappedKeyData);
        }
        if (passWrappedKeyData != null) {
            keyData.setWrappedPrivateData(passWrappedKeyData);
        }
        if (nonceData != null) {
            keyData.setNonceData(nonceData);
        }

        kra.destroyVolatileRequest(request.getRequestId());

        queue.markAsServiced(request);
        
        return keyData;
    }
    
    public KeyDataInfo createKeyDataInfo(IKeyRecord rec, UriInfo uriInfo) throws EBaseException {
        KeyDataInfo ret = new KeyDataInfo();
        String serial = null;
        serial = (rec.getSerialNumber()).toString();
         
        UriBuilder keyBuilder = uriInfo.getBaseUriBuilder();
        keyBuilder.path("/key/" + serial);
        ret.setKeyURL(keyBuilder.build().toString());
        return ret;
    }
    
}
