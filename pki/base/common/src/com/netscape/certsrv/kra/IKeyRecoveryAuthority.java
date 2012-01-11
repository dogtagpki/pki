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

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import netscape.security.x509.X500Name;

import org.mozilla.jss.crypto.CryptoToken;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.dbs.replicadb.IReplicaIDRepository;
import com.netscape.certsrv.policy.IPolicyProcessor;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.security.Credential;
import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.certsrv.security.ITransportKeyUnit;

/**
 * An interface represents key recovery authority. The
 * key recovery authority is responsibile for archiving
 * and recovering user encryption private keys.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface IKeyRecoveryAuthority extends ISubsystem {

    public static final String ID = "kra";

    public final static String PROP_NAME = "name";
    public final static String PROP_HTTP = "http";
    public final static String PROP_POLICY = "policy";
    public final static String PROP_DBS = "dbs";
    public final static String PROP_TOKEN = "token";
    public final static String PROP_SHARE = "share";
    public final static String PROP_PROTECTOR = "protector";
    public final static String PROP_LOGGING = "logging";
    public final static String PROP_QUEUE_REQUESTS = "queueRequests";
    public final static String PROP_STORAGE_KEY = "storageUnit";
    public final static String PROP_TRANSPORT_KEY = "transportUnit";
    public static final String PROP_NEW_NICKNAME = "newNickname";
    public static final String PROP_KEYDB_INC = "keydbInc";

    public final static String PROP_NOTIFY_SUBSTORE = "notification";
    public final static String PROP_REQ_IN_Q_SUBSTORE = "requestInQ";

    /**
     * Returns the name of this subsystem.
     * <P>
     * 
     * @return KRA name
     */
    public X500Name getX500Name();

    /**
     * Retrieves KRA request repository.
     * <P>
     * 
     * @return request repository
     */
    public IRequestQueue getRequestQueue();

    /**
     * Retrieves the key repository. The key repository
     * stores archived keys.
     * <P>
     */
    public IKeyRepository getKeyRepository();

    /**
     * Retrieves the Replica ID repository.
     * 
     * @return KRA's Replica ID repository
     */
    public IReplicaIDRepository getReplicaRepository();

    /**
     * Enables the auto recovery state. Once KRA is in the auto
     * recovery state, no recovery agents need to be present for
     * providing credentials. This feature is for enabling
     * user-based recovery operation.
     * <p>
     * 
     * @param cs list of agent credentials
     * @param on true if auto recovery state is on
     * @return current auto recovery state
     */
    public boolean setAutoRecoveryState(Credential cs[], boolean on);

    /**
     * Returns the current auto recovery state.
     * 
     * @return true if auto recvoery state is on
     */
    public boolean getAutoRecoveryState();

    /**
     * Adds credentials to the given authorizated recovery operation.
     * In distributed recovery mode, recovery agent login to the
     * agent interface and submit its credential for a particular
     * recovery operation.
     * 
     * @param id authorization identifier
     * @param creds list of credentials
     */
    public void addAutoRecovery(String id, Credential creds[]);

    /**
     * Removes a particular auto recovery operation.
     * 
     * @param id authorization identifier
     */
    public void removeAutoRecovery(String id);

    /**
     * Returns the number of required agents. In M-out-of-N
     * recovery schema, only M agents are required even there
     * are N agents. This method returns M.
     * 
     * @return number of required agents
     */
    public int getNoOfRequiredAgents() throws EBaseException;

    /**
     * Sets the number of required recovery agents
     * 
     * @param number number of agents
     */
    public void setNoOfRequiredAgents(int number) throws EBaseException;

    /**
     * Returns the current recovery identifier.
     * 
     * @return recovery identifier
     */
    public String getRecoveryID();

    /**
     * Returns a list of recovery identifiers.
     * 
     * @return list of auto recovery identifiers
     */
    public Enumeration<String> getAutoRecoveryIDs();

    /**
     * Returns the storage key unit that manages the
     * stoarge key.
     * 
     * @return storage key unit
     */
    public IStorageKeyUnit getStorageKeyUnit();

    /**
     * Returns the transport key unit that manages the
     * transport key.
     * 
     * @return transport key unit
     */
    public ITransportKeyUnit getTransportKeyUnit();

    /**
     * Returns the token that generates user key pairs for supporting server-side keygen
     * 
     * @return keygen token
     */
    public CryptoToken getKeygenToken();

    /**
     * Adds entropy to the token used for supporting server-side keygen
     * Parameters are set in the config file
     * 
     * @param logflag create log messages at info level to report entropy shortage
     */
    public void addEntropy(boolean logflag);

    /**
     * Returns the request listener that listens on
     * the request completion event.
     * 
     * @return request listener
     */
    public IRequestListener getRequestInQListener();

    /**
     * Returns policy processor of the key recovery
     * authority.
     * 
     * @return policy processor
     */
    public IPolicyProcessor getPolicyProcessor();

    /**
     * Returns the nickname of the transport certificate.
     * 
     * @return transport certificate nickname.
     */
    public String getNickname();

    /**
     * Sets the nickname of the transport certificate.
     * 
     * @param str nickname
     */
    public void setNickname(String str);

    /**
     * Returns the new nickname of the transport certifiate.
     * 
     * @return new nickname
     */
    public String getNewNickName() throws EBaseException;

    /**
     * Sets the new nickname of the transport certifiate.
     * 
     * @param name new nickname
     */
    public void setNewNickName(String name);

    /**
     * Logs event into key recovery authority logging.
     * 
     * @param level log level
     * @param msg log message
     */
    public void log(int level, String msg);

    /**
     * Creates a request object to store attributes that
     * will not be serialized. Currently, request queue
     * framework will try to serialize all the attribute into
     * persistent storage. Things like passwords are not
     * desirable to be stored.
     * 
     * @param id request id
     * @return volatile requests
     */
    public Hashtable<String, Object> createVolatileRequest(RequestId id);

    /**
     * Retrieves the request object.
     * 
     * @param id request id
     * @return volatile requests
     */
    public Hashtable<String, Object> getVolatileRequest(RequestId id);

    /**
     * Destroys the request object.
     * 
     * @param id request id
     */
    public void destroyVolatileRequest(RequestId id);

    public Vector<Credential> getAppAgents(
            String recoveryID) throws EBaseException;

    /**
     * Creates error for a specific recovery operation.
     * 
     * @param recoveryID recovery id
     * @param error error
     * @exception EBaseException failed to create error
     */
    public void createError(String recoveryID, String error)
            throws EBaseException;

    /**
     * Retrieves error by recovery identifier.
     * 
     * @param recoveryID recovery id
     * @return error message
     */
    public String getError(String recoveryID)
            throws EBaseException;

    /**
     * Retrieves PKCS12 package by recovery identifier.
     * 
     * @param recoveryID recovery id
     * @return pkcs12 package in bytes
     */
    public byte[] getPk12(String recoveryID)
            throws EBaseException;

    /**
     * Creates PKCS12 package in memory.
     * 
     * @param recoveryID recovery id
     * @param pk12 package in bytes
     */
    public void createPk12(String recoveryID, byte[] pk12)
            throws EBaseException;

    /**
     * Retrieves the transport certificate.
     */
    public org.mozilla.jss.crypto.X509Certificate getTransportCert();
}
