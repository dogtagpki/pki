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

import java.awt.Component;
import java.awt.event.KeyAdapter;
import java.awt.event.MouseAdapter;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.swing.JFrame;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import com.netscape.management.client.Framework;
import com.netscape.management.client.IPage;
import com.netscape.management.client.IResourceObject;
import com.netscape.management.client.ResourceModel;
import com.netscape.management.client.ResourceObject;
import com.netscape.management.client.ResourcePage;
import com.netscape.management.client.StatusItemProgress;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.LDAPUtil;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.nmclf.SuiConstants;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;

/**
 * A partially implemented class that is suitable to create
 * a server instance node.  It implements IServerObject, which
 * is required for all server objects, and INodeInfo, which
 * used to display common server information on the right hand pane.
 *
 * Only three methods are required to complete this class:
 * public abstract boolean run(IPage viewInstance, IResourceObject selectionList[]);
 * public abstract int getServerStatus();
 * public abstract void cloneFrom(String referenceDN);
 *
 */
public abstract class AbstractServerObject extends ResourceObject implements IServerObject,
INodeInfo, SuiConstants {
    public static ResourceSet _resource = TopologyInitializer._resource;

    public static int STATUS_UPDATE_INTERVAL = 15000;
    public static String RESOURCE_GROUP = "ServerObject";
    public static String ID_SERVER_STATUS = "SERVER_STATUS";

    protected ConsoleInfo _consoleInfo;
    protected NodeData _nodeData[], _nameNodeData;
    protected NodeDataPanel _nodeDataPanel;
    protected Hashtable _nodeDataTable = new Hashtable();
    protected IPage _viewInstance;
    protected ResourceObject _nodeObject;
    private boolean _showServerStatus = true;
    private int _serverStatus = STATUS_UNKNOWN;
    private long _lastStatusCheckTime;
    private NodeData _statusNodeData;
    private Vector _changeListeners = new Vector();
    private StatusThread _statusThread;

    // attributes of objectclass netscapeServer
    static String _serverDataKey[] = new String[]{ "cn", "serverProductName",
    "description", "administratorContactInfo", //"serverVersionNumber",
            "installationTimeStamp", "serverHostName", };

    // attributes of objectclass nsApplication
    static String _productDataKey[] = new String[]{ "nsProductName", //"description",
                "nsVendor", //"nsNickName",
                "nsProductVersion", "nsBuildNumber", "nsRevisionNumber",
                //"nsSerialNumber",
                        //"installationTimeStamp",
                        //"nsExpirationDate",
                        "nsBuildSecurity", };

    static String _editableDataKey[] = new String[]{ "serverProductName",
    "administratorContactInfo", "description", };

    static String _7bitDataKey[] = new String[]{ "serverProductName", };

    static String _displayDataKey[] = new String[]{ "serverProductName",
            "description", //"serverVersionNumber",
            "installationTimeStamp", "nsProductName",
            "nsVendor", "nsProductVersion", "nsBuildNumber", "nsRevisionNumber",
            //"nsBuildSecurity",
            };

    static String _nodeNameKey = "serverProductName";

    /**
    * Implements the IServerObject interface. Initializes the page with
    * the global information.
    *
    * @param info - global information.
    */
    public void initialize(ConsoleInfo info) {
        _consoleInfo = info;
        initializeNodeDataTable(info.getCurrentDN());

        String serverName = (String)_nodeDataTable.get(_nodeNameKey);
        if (serverName == null) {
            _nodeDataTable.put(_nodeNameKey,
                    _nodeDataTable.get("cn"));
        }
        setName((String)_nodeDataTable.get(_nodeNameKey));

        Vector v = initializeNodeDataVector(_displayDataKey);
        _nodeData = new NodeData[v.size()];
        v.copyInto(_nodeData);
    }

    /**
      * initialize configuration data table
      *
      * @param dn DN of the server instance entry (SIE)
      */
    private void initializeNodeDataTable(String dn) {
        initializeNodeDataTable(dn, _serverDataKey);
        initializeNodeDataTable(dn.substring(dn.indexOf(',') + 1),
                _productDataKey);
    }

    /**
      * initialize the configuration data
      *
      * @param dataKeys array of the configuration attribute name
      */
    protected Vector initializeNodeDataVector(String dataKeys[]) {
        Vector v = new Vector();
        for (int i = 0; i < dataKeys.length; i++) {
            String key = dataKeys[i];
            String value = (String)_nodeDataTable.get(key);
            v.addElement( new NodeData(key,
                    _resource.getString(RESOURCE_GROUP, key), value,
                    isEditable(key), is7bit(key)));
            if (key.equals(_nodeNameKey)) {
                _nameNodeData = (NodeData) v.elementAt(v.size() - 1);
            }
        }

        if (_showServerStatus) {
            String description =
                    _resource.getString(RESOURCE_GROUP, ID_SERVER_STATUS);
            String status = getServerStatusString(_serverStatus);
            v.addElement(_statusNodeData =
                    new NodeData(ID_SERVER_STATUS, description, status));
        }

        return v;
    }

    /**
      * @param key name of the attribute
      * @return true if editable
      */
    protected boolean isEditable(String key) {
        for (int i = 0; i < _editableDataKey.length; i++)
            if (_editableDataKey[i].equals(key))
                return true;
        return false;
    }

    /**
      * @param key name of the attribute
      * @return true field accepts only 7 bit input
      */
    protected boolean is7bit(String key) {
        for (int i = 0; i < _7bitDataKey.length; i++)
            if (_7bitDataKey[i].equals(key))
                return true;
        return false;
    }

    /**
      * query and initialize the attribute for the SIE
      *
      * @param dn DN of the SIE
      * @param attribute list of attribute names
      */
    protected void initializeNodeDataTable(String dn, String[] attribute) {
        try {
            LDAPAttribute attr;
            LDAPConnection ldc = _consoleInfo.getLDAPConnection();
            LDAPEntry entry = ldc.read(dn);
            String locale = LDAPUtil.getLDAPAttributeLocale();

            for (int i = 0; i < attribute.length; i++) {
                attr = entry.getAttribute(attribute[i], locale);
                if (attr != null) {
                    String data = LDAPUtil.flatting(attr);
                    if (attribute[i].equals("installationTimeStamp")) {
                        data = LDAPUtil.formatDateTime(data);
                    }
                    _nodeDataTable.put(attribute[i], data);
                }
            }
        } catch (LDAPException e) {
            Debug.println(
                    "AbstractServerObject.initializeNodeDataTable: " +
                    e + " DN="+dn);
        }
    }

    /**
      * return the configuration panel
      *
      * @return configuration panel
      */
    public Component getCustomPanel() {
        _nodeDataPanel = new NodeDataPanel(getIcon(),(String)_nodeDataTable.get(_nodeNameKey), this, true);
		_nodeDataPanel.setHelpTopic("admin", "topology-servernode");
        if (_showServerStatus && _statusThread == null) {
            Debug.println(7, "AbstractServerObject.getCustomPanel():Create status thread");
            _statusThread = new StatusThread();
            _statusThread.start();

        }
        return _nodeDataPanel;
    }


    /**
      * Number of entries for this node.
      * Implements INodeInfo
      *
      * @return number of entries
      */
    public int getNodeDataCount() {
        return _nodeData.length;
    }


    /**
      * Return node entry at specified index.
      * Implements INodeInfo
      *
      * @return the specified node data
      */
    public NodeData getNodeData(int index) {
        return _nodeData[index];
    }

    /**
      * Replaces local node data value.  The local node is
      * matched by comparing its name with newData's name.
      */
    public void replaceNodeDataValue(NodeData newData) {
        for (int index = 0; index < _nodeData.length; index++) {
            if (_nodeData[index].getName().equals(newData.getName())) {
                _nodeData[index].setValue(newData.getValue());
                return;
            }
        }
    }


    // Used to temporarily grab input for JFrame glass pane, which disables
    // user input while a task thread is being run.
    private static KeyAdapter _tmpGrabKey = new KeyAdapter() {};
    private static MouseAdapter _tmpGrabMouse = new MouseAdapter() {};

    /**
     * Grab or release user input.
     *
     * @param viewInstance  console view
     * @param value         grab user input if true, release if false
     */
    private synchronized void setGrabAllInput(IPage viewInstance,
            boolean value) {
        JFrame frame = viewInstance.getFramework().getJFrame();
        Component glassPane = frame.getGlassPane();
        if (value) {
            glassPane.addKeyListener(_tmpGrabKey);
            glassPane.addMouseListener(_tmpGrabMouse);
            glassPane.setVisible(true);
        } else {
            glassPane.removeKeyListener(_tmpGrabKey);
            glassPane.removeMouseListener(_tmpGrabMouse);
            glassPane.setVisible(false);
        }
    }


    /**
      * Display the busy signal. Called from a task thread.
      *
      * @param viewInstance  console view
      * @param isBusy        boolean flag to indicate busy
      * @param status        status text to be displayed
      */
    private synchronized void setBusyIndicator(IPage viewInstance,
            boolean isBusy, String status) {
        setGrabAllInput(viewInstance, isBusy);

        if ((viewInstance instanceof ResourcePage) == false) {
            return;
        }
        ResourcePage rp = (ResourcePage) viewInstance;
        ResourceModel rpm = (ResourceModel) rp.getModel();

        if (isBusy == true) {
            ((Framework) viewInstance.getFramework()).setBusyCursor(
                    true); //setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
                    rpm.fireChangeStatusItemState(null,
                    Framework.STATUS_TEXT, status);
            rpm.fireChangeStatusItemState(null,
                    ResourcePage.STATUS_PROGRESS,
                    StatusItemProgress.STATE_BUSY);
        } else {
            ((Framework) viewInstance.getFramework()).setBusyCursor(
                    false); //setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
                    rpm.fireChangeStatusItemState(null,
                    Framework.STATUS_TEXT, status);
            rpm.fireChangeStatusItemState(null,
                    ResourcePage.STATUS_PROGRESS, Integer.valueOf(0));
        }
    }

    /**
         * Inner class for opening a server console in a separate thread.
         * The interaction with the popup dialog allows the thread to be
         * killed in case the operation fails. This prevents the main
         * console from becoming inoperable as a result of a failure.
         */
    class ServerRunThread extends Thread {
        IResourceObject _node;
        IPage _viewInstance;
        IResourceObject[]_selection;

        public ServerRunThread(IResourceObject node,
                IPage viewInstance, IResourceObject[] selection) {
            _node = node;
            _viewInstance = viewInstance;
            _selection = selection;
        }

        public void run() {
            // Catch exception here as a defensive measure to prevent
            // the run method from exiting without unsetting the busy
            // indicator which effectively hangs the console.
            try {
                AbstractServerObject.this.setBusyIndicator(
                        _viewInstance, true,
                        _resource.getString("status", "openingServer"));
                _node.run(_viewInstance, _selection);
            } catch (Exception e) {
                 if (Debug.isEnabled()) {
                     e.printStackTrace();
                 }
                 Debug.println(0, "AbstractServerObject.ServerRunThread " +e);
            }
            finally { AbstractServerObject.this.setBusyIndicator(
                    _viewInstance, false, "");
            } }
    }


    /**
         * Notification that an entry value has changed after user edit.
         * Implements INodeInfo
         */
    public void actionNodeDataChanged(NodeData data) {
        replaceNodeDataValue(data);

        if (data.getID().equals(NodeDataPanel.ID_OPEN)) {
            if (Debug.timeTraceEnabled()) {
                Debug.println(Debug.TYPE_RSPTIME,
                        "Open " + getName() + " ...");
            }

            IResourceObject[] selection = new IResourceObject[]{this};
            if (_viewInstance instanceof ResourcePage) {
                selection = ((ResourcePage)_viewInstance).getSelection();
            }
            ServerRunThread thread =
                    new ServerRunThread(this, _viewInstance, selection);
            thread.start();
            return;
        }

        String dn = _consoleInfo.getCurrentDN();
        LDAPAttribute attr =
                new LDAPAttribute(data.getID(), (String) data.getValue());
        LDAPModification modification =
                new LDAPModification(LDAPModification.REPLACE, attr);
        LDAPConnection ldc = _consoleInfo.getLDAPConnection();
        try {
            ldc.modify(dn, modification);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_ATTRIBUTE) {
                try {
                    modification =
                            new LDAPModification(LDAPModification.ADD,
                            attr);
                    ldc.modify(dn, modification);
                } catch (LDAPException ex) {
                    Debug.println(
                            "AbstractServerObject.actionNodeDataChanged() " +
                            ex);
                }
            } else {
                Debug.println(
                        "AbstractServerObject.actionNodeDataChanged() " + e);
            }
        }
        if (data.getID().equals(_nodeNameKey)) {
            _nodeDataPanel.setTitle((String) data.getValue());
            _nodeDataTable.put(_nodeNameKey, data.getValue());
            _nameNodeData.setValue(data.getValue());
            setName((String) data.getValue());
            if (_viewInstance != null &&
                    _viewInstance instanceof ResourcePage) {
                ResourcePage page = (ResourcePage)_viewInstance;
                if (page.getTreeModel() instanceof ResourceModel &&
                        _nodeObject != null) {
                    _nodeObject.setName(getName());
                    ((ResourceModel) page.getTreeModel()).
                            fireTreeNodeChanged(_nodeObject);
                }
            }
        }
    }

    /**
      * Set the Node Object
      * Node Object is a ResourceObjest in the page ResourceModel that is referencing
      * this AbstractServerObject. It is used for firing TreeNodeChange events after
      * a name change, so that a new name can be immediately reflected in the tree.
      *
      * @param nodeObject a nodeObject that represents this AbstractServerObject in the tree
      */
    public void setNodeObject(ResourceObject nodeObject) {
        _nodeObject = nodeObject;
    }

    /**
      * set the new server status
      *
      * @param b new server status - whether it is on or off.
      */
    protected void setShowServerStatus(boolean b) {
        _showServerStatus = b;
    }

    /**
      * get server status
      *
      * @return server status. on/off
      */
    protected boolean getShowServerStatus() {
        return _showServerStatus;
    }

    /**
      * Uselect the node (override method)
      *
      * For the immediate garbage collection release the reference to nodeDataPanel,
      * kill status thread.
      *
         * If extending this class and overriding this method, be sure to call
         * this method via super.unselect(...).
      *
      * @param viewInstance current Page
      */
    public void unselect(IPage viewInstance) {
        _nodeDataPanel = null;
        if (_statusThread != null) {
            Debug.println(7, "AbstractServerObject.unselect: Destroy status thread");
            _statusThread.halt();
            _statusThread = null;
        }
    }

    /**
      * Select the specified instance.
         *
         * If extending this class and overriding this method, be sure to call
         * this method via super.select(...).
      *
      * @param viewInstance view selected
      */
    public void select(IPage viewInstance) {
        super.select(viewInstance);
        _viewInstance = viewInstance;
    }

    /**
      * map the server status to display string
      *
      * @param serverStatus server status
      * @return mapped string for the server status
      */
    public static String getServerStatusString(int serverStatus) {
        switch (serverStatus) {
        case STATUS_UNKNOWN:
            return _resource.getString("server","unknown");

        case STATUS_STARTED:
            return _resource.getString("server","started");

        case STATUS_STOPPED:
            return _resource.getString("server","stopped");

        case STATUS_ALERT:
            return _resource.getString("server","alert");

        default:
            return "";
        }
    }


    class StatusThread extends Thread {
        private Thread _thread;
        private boolean _running, _sleeping;

        public StatusThread() {
            super("StatusThread");
            setPriority(MIN_PRIORITY);
            _thread = this;
        }

        public void halt() {
            _running = false;
            if (_sleeping) {
                _thread.interrupt();
            }
        }

        public void run() {
            _running = true;
            _sleeping = false;

            // On Solaris with native threads StatusThread might be
            // activated before any change listener is registered
            while (_running && _changeListeners.size() == 0) {
                try {
                    Debug.println(7, "AbstractServerObject.StatusThread: waiting for change listeners to register");
                    _sleeping = true;
                    Thread.currentThread();
                    Thread.sleep(1000);
                    _sleeping = false;
                } catch (Exception e) {}
            }

            if (_lastStatusCheckTime != 0) {
                /**
                  * If we checked status within last STATUS_UPDATE_INTERVAL
                  * then sleep until STATUS_UPDATE_INTERVAL expires.
                 */
                try {
                    long delta = System.currentTimeMillis() -
                            _lastStatusCheckTime;
                    if (STATUS_UPDATE_INTERVAL > delta) {
                        Debug.println(7,
                                "AbstractServerObject.StatusThread: last check delta = " +
                                delta / 1000. + " sleep = " +
                                (STATUS_UPDATE_INTERVAL - delta) / 1000.);
                        _sleeping = true;
                        sleep(STATUS_UPDATE_INTERVAL - delta);
                        _sleeping = false;
                    } else {
                        Debug.println(7,
                                "AbstractServerObject.StatusThread: last check delta = " +
                                delta / 1000.);
                    }
                } catch (Exception e) {
                    Debug.println(9, "AbstractServerObject.StatusThread: Status thread stop because "+e);
                    return;
                }
            }

            while (_running) {
                try {
                    long t1, t0 = System.currentTimeMillis();
                    _serverStatus = getServerStatus();
                    _lastStatusCheckTime = t1 = System.currentTimeMillis();
                    Debug.println(7,
                            "AbstractServerObject.StatusThread: Check Status CGI = " +
                            _serverStatus + " exe time: " +
                            ((t1 - t0) / 1000.));

                    _statusNodeData.setValue(
                            getServerStatusString(_serverStatus));
                    ChangeEvent event = new ChangeEvent(_statusNodeData);
                    Enumeration e = _changeListeners.elements();
                    Debug.println(7,
                            "AbstractServerObject.StatusThread: change listener count=" +
                            _changeListeners.size());
                    while (e.hasMoreElements()) {
                        ChangeListener l = (ChangeListener) e.nextElement();
                        l.stateChanged(event);
                    }

                    if (_running) {
                        _sleeping = true;
                        sleep(STATUS_UPDATE_INTERVAL);
                        _sleeping = false;
                    }
                } catch (InterruptedException e) {
                    Debug.println(9, "AbstractServerObject.StatusThread: Status thread stop because "+e);
                }
            }
        }
    }

    /**
      * Adds change listener
      * allows implenting class to send change notifictions about NodeData
      * Implements INodeInfo
      */
    public void addChangeListener(ChangeListener l) {
        _changeListeners.addElement(l);
    }

    /**
      * Removes change listener
      * Implements INodeInfo
      */
    public void removeChangeListener(ChangeListener l) {
        _changeListeners.removeElement(l);
    }

    public abstract boolean run(IPage viewInstance,
            IResourceObject selectionList[]);

    public abstract int getServerStatus();

    public abstract void cloneFrom(String referenceDN);

    /**
     * Specifies ACL menu enabled/disabled state.
     * @return true if server allows ACLs to be set
     */
    public boolean isACLEnabled() {
        return true;
    }

    /**
      * Specifies Cloning menu enabled/disabled state.
      * @return true if server allows cloning operations
      */
    public boolean isCloningEnabled() {
        return false;
    }

    /**
      * Specifies Migration menu enabled/disabled state.
      * @return true if server allows migration operations
      */
    public boolean isMigrationEnabled() {
        return true;
    }
}
