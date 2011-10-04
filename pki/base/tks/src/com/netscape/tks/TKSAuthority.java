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
package com.netscape.tks;

import java.io.*;
import java.net.*;
import java.util.*;
import java.math.*;
import java.security.*;
import java.security.cert.*;
import netscape.security.x509.*;
import netscape.security.util.*;
import com.netscape.cmscore.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.dbs.repository.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.dbs.crldb.*;
import com.netscape.cmscore.dbs.*;
import com.netscape.certsrv.dbs.crldb.ICRLRepository;


import org.mozilla.jss.pkix.primitive.*;
import com.netscape.cmscore.util.Debug;
import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.asn1.*;
import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.security.*;
import com.netscape.certsrv.policy.*;

import com.netscape.certsrv.dbs.crldb.*;
import com.netscape.certsrv.apps.*;
import java.security.cert.*;

public class TKSAuthority implements IAuthority, ISubsystem {
	protected ILogger mLogger = CMS.getLogger();
	private String mNickname = null;  
	private ISubsystem mOwner;
	private IConfigStore mConfig = null;
	protected String mId = null;
	public static final String PROP_NICKNAME = "nickName";

   /**
     * Retrieves the request queue for the Authority.
     * <P>
     * @return the request queue.
     */
    public IRequestQueue getRequestQueue() {
        return null;
    }
    /**
     * Registers request completed class.
     */
    public void registerRequestListener(IRequestListener listener) {
    }

   /**
     * Registers pending request class.
     */
    public void registerPendingListener(IRequestListener listener) {
    }
	    /**
     * log interface
     */
   public void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_TKS,
            level, msg);
    }
   /**
     * nickname of signing (id) cert
     */
    public void setNickname( String nickname ) {
        mNickname = nickname;
    }

    public String getNickname() {
        CMS.debug("Error: TKSAuthority::getNickname - nickname of signing (id) cert");
        return mNickname;
    }
    public String getOfficialName() {
        return "tks";
    }
	
	 /**
     * Initializes this subsystem.
     * <P>
     *
     * @param owner owner of this subsystem
     * @param config configuration of this subsystem
     * @exception EBaseException failed to initialize this RA
     */
    public void init(ISubsystem owner, IConfigStore config) throws
            EBaseException {
        mOwner = owner;

        mConfig = config;
		//mNickname = mConfig.getString(PROP_NICKNAME);
       CMS.debug("TKS Authority (" +
            getId() + "): " + "Initialized Request Processor.");

    }
	    /**
     * Notifies this subsystem if owner is in running mode.
     *
     * @exception EBaseException failed to start up
     */
    public void startup() throws EBaseException {

        // Note that we use our instance id for registration.
        // This helps us to support multiple instances
        // of a subsystem within server.

    }
    /**
     * Stops this system. The owner may call shutdown
     * anytime after initialization.
     * <P>
     */
   public void shutdown() {

        getLogger().log(ILogger.EV_SYSTEM, ILogger.S_TKS, 
            ILogger.LL_INFO, "TKSAuthority is stopped");

    }
    /**
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }
    public String getId() {
        return mId;
    }

	/**
     * Sets subsystem identifier.
     *
     * @param id subsystem id
     * @exception EBaseException failed to set id
     */
    public void setId(String id) throws EBaseException {
        mId = id;
    }
	 /**
     * Retrieves logger from escrow authority.
     *
     * @return logger
     */
    public ILogger getLogger() {
        return CMS.getLogger();
    }

}
