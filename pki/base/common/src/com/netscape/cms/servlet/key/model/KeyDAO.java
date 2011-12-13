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
import java.util.List;

import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.cms.servlet.request.model.RecoveryRequestData;

/**
 * @author alee
 *
 */
public class KeyDAO {

    private IKeyRepository repo;
    private int maxSize = 100;
    private int maxTime = 20;
    
    public KeyDAO() {
        IKeyRecoveryAuthority kra = null;
        kra = ( IKeyRecoveryAuthority ) CMS.getSubsystem( "kra" );
        repo = kra.getKeyRepository();
    }
    /**
     * This will find the keys in the database matching the specified search parameters
     * Needs input validation and probably paging, maybe using the vlv functions
     * @throws EBaseException 
     */
    public List<KeyDataInfo> listKeys(String filter, UriInfo uriInfo) throws EBaseException {
        List <KeyDataInfo> list = new ArrayList<KeyDataInfo>();         
        Enumeration<IKeyRecord> e = null;
        
        e = repo.searchKeys(filter, maxSize, maxTime);
         
        if (e == null) {
            throw new EBaseException("search results are null");
        }
        
        while (e.hasMoreElements()) {
            IKeyRecord rec = e.nextElement();
            list.add(createKeyDataInfo(rec, uriInfo));
        }
        return list;
    }
    
    public KeyData getKey(String keyId, RecoveryRequestData data) throws EBaseException {
        KeyData keyData = null;
        BigInteger serial = new BigInteger(keyId);
        
        // get wrapped key
        IKeyRecord rec = repo.readKeyRecord(serial);
        if (rec == null) {
            // key does not exist
            // log the error
            return null;  
        }
        // TODO unwrap the key and wrap with the credential in RecoveryRequestData
        // need to figure out how to do this with jmagne 
        
        return keyData;
    }
    
    public KeyDataInfo createKeyDataInfo(IKeyRecord rec, UriInfo uriInfo) throws EBaseException {
        KeyDataInfo ret = new KeyDataInfo();
        String serial = null;
        serial = (rec.getSerialNumber()).toString();
         
        UriBuilder keyBuilder = uriInfo.getBaseUriBuilder();
        keyBuilder.path("/key/" + serial);
        ret.setKeyURL(keyBuilder.build().toString());
        
        // clientID = rec.getClientID();
        // TODO add other fields as needed
        return ret;
    }
    
}
