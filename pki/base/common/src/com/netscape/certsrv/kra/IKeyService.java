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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.kra;


import java.math.BigInteger;
import java.util.Hashtable;
import java.security.cert.X509Certificate;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.security.*;
import netscape.security.x509.X509CertImpl;


/**
 * An interface representing a recovery service.
 * <P>
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface IKeyService {

    /**
     * Retrieves number of agent required to perform
     * key recovery operation.
     * 
     * @return number of required recovery agents
     * @exception EBaseException failed to retrieve value
     */
    public int getNoOfRequiredAgents() throws EBaseException;

    /**
     * Performs administrator-initiated key recovery.
     *
     * @param kid key identifier
     * @param creds list of credentials (id and password)
     * @param pwd password to protect PKCS12
     * @param cert certificate embedded in PKCS12
     * @param delivery delivery mechanism
     * @return pkcs12
     * @exception EBaseException failed to perform recovery
     */
    public byte[] doKeyRecovery(BigInteger kid,
        Credential creds[], String pwd, X509CertImpl cert,
        String delivery, String nickname) throws EBaseException;

    /**
     * Retrieves recovery identifier.
     *
     * @return recovery id
     */
    public String getRecoveryID();

    /**
     * Creates recovery parameters for the given recovery operation.
     *
     * @param recoveryID recovery id
     * @return recovery parameters
     * @exception EBaseException failed to create
     */
    public Hashtable createRecoveryParams(String recoveryID) 
        throws EBaseException;

    /**
     * Destroys recovery parameters for the given recovery operation.
     *
     * @param recoveryID recovery id
     * @exception EBaseException failed to destroy
     */
    public void destroyRecoveryParams(String recoveryID) 
        throws EBaseException;

    /**
     * Retrieves recovery parameters for the given recovery operation.
     *
     * @param recoveryID recovery id
     * @return recovery parameters
     * @exception EBaseException failed to retrieve
     */
    public Hashtable getRecoveryParams(String recoveryID) 
        throws EBaseException;

    /**
     * Adds password in the distributed recovery operation.
     *
     * @param recoveryID recovery id
     * @param uid agent uid
     * @param pwd agent password
     * @exception EBaseException failed to add
     */
    public void addDistributedCredential(String recoveryID, 
        String uid, String pwd) throws EBaseException;

    /**
     * Retrieves credentials in the distributed recovery operation.
     *
     * @param recoveryID recovery id
     * @return agent's credentials
     * @exception EBaseException failed to retrieve
     */
    public Credential[] getDistributedCredentials(String recoveryID) 
        throws EBaseException;
}
