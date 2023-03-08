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
package com.netscape.cmscore.request;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.DBSSession;
import com.netscape.cmscore.dbs.DBSubsystem;

/**
 * RequestSubsystem
 * <p>
 * This class is responsible for managing storage of request objects in the local database.
 * <p>
 * TODO: review this It provides: + registration of LDAP/JAVA mapping classes with the DBSubsystem + creation of
 * RequestQueue storage in the database + retrieval of existing RequestQueue objects from the database
 * <p>
 *
 * @author thayes
 * @version $Revision$, $Date$
 */
public class RequestSubsystem {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RequestSubsystem.class);

    public final static String ID = "request";

    DBSubsystem dbSubsystem;

    public RequestSubsystem() {
    }

    /**
     * Creates a new request queue.
     * (Currently unimplemented. Just use getRequestQueue to create
     * an in-memory queue.)
     * <p>
     *
     * @param name The name of the queue object. This name can be used
     *            in getRequestQueue to retrieve the queue later.
     * @exception EBaseException failed to create request queue
     */
    public void createRequestQueue(String name)
            throws EBaseException {

        /*
         String dbName = makeQueueName(name);
         DBSSession dbs = createDBSSession();

         // Create Repository record here

        dbs.add(dbName, r);
        */
    }

    //
    // Subsystem methods:
    //   getId, setId, init, startup, shutdown, getConfigStore
    //

    /**
     * Implements Subsystem.getId
     * <p>
     *
     * @see Subsystem#getId
     */
    public String getId() {
        return mId;
    }

    // Subsystem.setId
    public void setId(String id)
            throws EBaseException {
        mId = id;
    }

    // Subsystem.init
    public void init(ConfigStore config, DBSubsystem dbSubsystem) {
        this.mConfig = config;
        this.dbSubsystem = dbSubsystem;
    }

    /**
     * Implements Subsystem.startup
     * <p>
     *
     * @see Subsystem#startup
     */
    public void startup() {
        logger.info("RequestSubsystem: Request subsystem started");
    }

    public void shutdown() {
        logger.info("RequestSubsystem: Request subsystem stopped");
    }

    public ConfigStore getConfigStore() {
        return mConfig;
    }

    //
    // Create a database session in the default database
    // system.
    //
    protected DBSSession createDBSSession()
            throws EBaseException {
        return dbSubsystem.createSession();
    }

    //
    // Make a queue name
    //
    protected String makeQueueName(String name) {
        return "cn=" + name + "," + dbSubsystem.getBaseDN();
    }

    // Instance variables

    private ConfigStore mConfig;
    private String mId = ID;
}
