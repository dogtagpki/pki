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
 * @version $Revision$, $Date$
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
    * is async recovery request status APPROVED -
    *   i.e. all required # of recovery agents approved
    * @param reqID request id
    * @return true if  # of recovery required agents approved; false otherwise
    */
    public boolean isApprovedAsyncKeyRecovery(String reqID)
        throws EBaseException;

   /**
    * get async recovery request initiating agent
    * @param reqID request id
    * @return agentUID
    */
    public String getInitAgentAsyncKeyRecovery(String reqID)
        throws EBaseException;

    /**
     * Initiate asynchronous key recovery
     * @param kid key identifier
     * @param cert certificate embedded in PKCS12
     * @return requestId
     * @exception EBaseException failed to initiate async recovery
     */
    public String initAsyncKeyRecovery(BigInteger kid, X509CertImpl cert, String agent)
         throws EBaseException;

    /**
     * add approving agent in asynchronous key recovery
     * @param reqID request id
     * @param agentID agent id
     * @exception EBaseException failed to initiate async recovery
     */
    public void addAgentAsyncKeyRecovery(String reqID, String agentID)
         throws EBaseException;

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
        String delivery, String nickname, String agent) throws EBaseException;

     /**
     * Async Recovers key for administrators. This method is
     * invoked by the agent operation of the key recovery servlet.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST used whenever
     * a user private key recovery request is made (this is when the DRM
     * receives the request)
     * <li>signed.audit LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST_PROCESSED used whenever
     * a user private key recovery request is processed (this is when the DRM
     * processes the request)
     * </ul>
     * @param reqID  request id
     * @param password password of the PKCS12 package
     * subsystem
     * @exception EBaseException failed to recover key
     * @return a byte array containing the key
     */
    public byte[] doKeyRecovery(
        String reqID,
        String password)
        throws EBaseException;

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
