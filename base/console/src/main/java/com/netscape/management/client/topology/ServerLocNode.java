/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.topology;

import javax.swing.*;
import javax.swing.tree.*;
import com.netscape.management.client.*;
import java.net.URL;
import java.net.MalformedURLException;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.*;

/**
	* Implement ResourceObject which used to represent Netscape topology model's node.
	*
	* @author  ahakim, terencek
	* @version %I%, %G%
	*/
public class ServerLocNode extends ResourceObject {
    String _sDN;
    ServiceLocator _sl;
    boolean _fLoaded;
    public ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");

    /**
     * constructor
     *
     * @param sl ServiceLoactor to locate other servers.
     */
    public ServerLocNode(ServiceLocator sl) {
        _sl = sl;
        _fLoaded = false;
    }

    /**
      * get the DN of the node
      *
      * @return the DN of the node
      */
    public String getDN() {
        return _sDN;
    }

    /**
      * set the DN of the tree node
      *
      * @param newDN DN of the tree node
      */
    public void setDN(String newDN) {
        _sDN = newDN;
    }

    /**
      * return the service locator of the node
      *
      * @return service locator of the node
      */
    public ServiceLocator getServiceLocator() {
        return _sl;
    }

    /**
      * check whether it has a children with the given name
      *
      * @param name display name of the children
      * @return null if the child is not find. Otherwise, it will return the child object.
      */
    public Object searchChildByName(String name) {
        // BUGBUG: need to implement this as a hashtable
        // PERFORMANCE

        return null;
    }

    //
    //  utility class
    //

    /**
     * reload the information in the node. The subclass object needs
     * to implement this function in order to refresh the latest
     * information. The subclass object will use this function to
     * populate or retrieve all the child node.
     */
    public void reload() {
        // do nothing
        _fLoaded = true;
    }

    /**
      * checked whether the node is loaded. If the node is not loaded, the
      * caller can call reload() to load the node information.
      *
      * @return whether the node is loaded or not.
      */
    public boolean isLoaded() {
        return _fLoaded;
    }

    /**
      * Invokes the sync-task-sie-data runtime command on the specified
      * admin server. Needed to resync the admin server's shapshot of the
      * sie entries in the DS without an admin server restart.
      *
      * @param consoleInfo  the ConsoleInfo containing the required info to
      *                     run the command on the admin server
      */
    protected synchronized void syncTaskSIEData(ConsoleInfo consoleInfo) {
        try {
            URL taskurl = new URL(consoleInfo.getAdminURL() + "admin-serv/commands/sync-task-sie-data");
            AdmTask task = new AdmTask(taskurl,
                    consoleInfo.getAuthenticationDN(),
                    consoleInfo.getAuthenticationPassword());
            int execStatus = task.exec();
            if (execStatus == 0) {
                Debug.println(
                        "TRACE ServerLocNode.syncTaskSIEData: command status = " +
                        execStatus);
            } else {
                Debug.println(
                        "ERROR ServerLocNode.syncTaskSIEData: command status = " +
                        execStatus);
            }
        } catch (MalformedURLException e) {
            Debug.println(
                    "ERROR ServerLocNode.syncTaskSIEData: Bad URL: " + e);
        }
        catch (Exception e) {
            Debug.println(
                    "ERROR ServerLocNode.syncTaskSIEData: exception: " + e);
        }
    }

    /**
      * turn on busy cursor
      */
    private void busyOn() {
        JFrame f = UtilConsoleGlobals.getActivatedFrame();
        if (f != null && f instanceof Framework) {
            ((Framework)f).setBusyCursor(true);
        }
    }

    /**
      * turn off busy cursor
      */
    private void busyOff() {
        JFrame f = UtilConsoleGlobals.getActivatedFrame();
        if (f != null && f instanceof Framework) {
            ((Framework)f).setBusyCursor(false);
        }
    }

    /**
      * return the child at the given position.
      *
      * @param index position
      * @return child at the given position
      */
    public TreeNode getChildAt(int index) {
        if (!isLoaded()) {
            _fLoaded = true;
            String sName = getName();
            if (sName == null) {
                sName = "";
            }
            busyOn();
            reload();
            busyOff();
        }
        return super.getChildAt(index);
    }

    /**
      * number of children under this node
      *
      * @return number of children under this node
      */
    public int getChildCount() {
        if (!isLoaded()) {
            _fLoaded = true;
            String sName = getName();
            if (sName == null) {
                sName = "";
            }
            busyOn();
            reload();
            busyOff();
        }
        return super.getChildCount();
    }

    /**
      * check whether this node is leaf node or not
      */
    public boolean isLeaf() {
        if (this instanceof ServerNode)
            return true;
        return false;
    }
}
