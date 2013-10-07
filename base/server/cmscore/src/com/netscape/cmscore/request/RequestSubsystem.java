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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.dbs.IDBSSession;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.INotify;
import com.netscape.certsrv.request.IPolicy;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.IRequestSubsystem;
import com.netscape.certsrv.request.IService;
import com.netscape.cmscore.dbs.DBSubsystem;

/**
 * RequestSubsystem
 * <p>
 * This class is reponsible for managing storage of request objects in the local database.
 * <p>
 * TODO: review this It provides: + registration of LDAP/JAVA mapping classes with the DBSubsystem + creation of
 * RequestQueue storage in the database + retrieval of existing RequestQueue objects from the database
 * <p>
 *
 * @author thayes
 * @version $Revision$, $Date$
 */
public class RequestSubsystem
        implements IRequestSubsystem, ISubsystem {

    public final static String ID = IRequestSubsystem.SUB_ID;

    // singleton enforcement

    private static RequestSubsystem mInstance = new RequestSubsystem();

    public static RequestSubsystem getInstance() {
        return mInstance;
    }

    private RequestSubsystem() {
    }

    // end singleton enforcement.

    //
    // Create a new request queue.  The LDAP DN for the entry
    // in the database is supplied by the caller.
    //
    public void createRequestQueue(String name)
            throws EBaseException {

        /*
         String dbName = makeQueueName(name);
         IDBSSession dbs = createDBSSession();

         // Create Repository record here

        dbs.add(dbName, r);
        */
    }

    public IRequestQueue
            getRequestQueue(String name, int increment, IPolicy p, IService s, INotify n)
                    throws EBaseException {
        return getRequestQueue(name, increment, p, s, n, null);
    }

    public IRequestQueue
            getRequestQueue(String name, int increment, IPolicy p, IService s, INotify n,
                    INotify pendingNotifier)
                    throws EBaseException {
        RequestQueue rq = new RequestQueue(name, increment, p, s, n, pendingNotifier);

        // can't do this here because the service depends on getting rq
        // (to get request) and since this method hasn't returned it's rq is null.
        //rq.recover();

        return rq;
    }

    //
    // ISubsystem methods:
    //   getId, setId, init, startup, shutdown, getConfigStore
    //

    /**
     * Implements ISubsystem.getId
     * <p>
     *
     * @see ISubsystem#getId
     */
    public String getId() {
        return mId;
    }

    // ISubsystem.setId
    public void setId(String id)
            throws EBaseException {
        mId = id;
    }

    // ISubsystem.init
    public void init(ISubsystem parent, IConfigStore config) {
        mParent = parent;
        mConfig = config;
    }

    /**
     * Implements ISubsystem.startup
     * <p>
     *
     * @see ISubsystem#startup
     */
    public void startup()
            throws EBaseException {
        mLogger = CMS.getLogger();

        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_REQQUEUE, ILogger.LL_INFO,
                "Request subsystem started");
    }

    public void shutdown() {

        if (mLogger != null) {
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_REQQUEUE, ILogger.LL_INFO,
                    "Request subsystem stopped");
        }
    }

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    //
    // Access to the DBSubsystem environment value
    //
    protected IDBSubsystem getDBSubsystem() {
        return DBSubsystem.getInstance();
    }

    //
    // Create a database session in the default database
    // system.
    //
    protected IDBSSession createDBSSession()
            throws EBaseException {
        return getDBSubsystem().createSession();
    }

    //
    // Make a queue name
    //
    protected String makeQueueName(String name) {
        IDBSubsystem db = getDBSubsystem();

        return "cn=" + name + "," + db.getBaseDN();
    }

    // Instance variables

    private IConfigStore mConfig;
    @SuppressWarnings("unused")
    private ISubsystem mParent;
    private String mId = IRequestSubsystem.SUB_ID;

    protected ILogger mLogger;
}
