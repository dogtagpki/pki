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
package com.netscape.admin.certsrv;

import java.awt.Cursor;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.ResourceBundle;

import javax.swing.Icon;
import javax.swing.JFrame;

import com.netscape.admin.certsrv.config.install.InstallWizard;
import com.netscape.admin.certsrv.config.install.InstallWizardInfo;
import com.netscape.admin.certsrv.task.CMSConfigCert;
import com.netscape.admin.certsrv.task.CMSRemove;
import com.netscape.admin.certsrv.task.CMSRestart;
import com.netscape.admin.certsrv.task.CMSStart;
import com.netscape.admin.certsrv.task.CMSStartDaemon;
import com.netscape.admin.certsrv.task.CMSStatus;
import com.netscape.admin.certsrv.task.CMSStop;
import com.netscape.admin.certsrv.wizard.IWizardDone;
import com.netscape.admin.certsrv.wizard.WizardWidget;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.TaskId;
import com.netscape.management.client.Framework;
import com.netscape.management.client.IMenuInfo;
import com.netscape.management.client.IMenuItem;
import com.netscape.management.client.IPage;
import com.netscape.management.client.IResourceObject;
import com.netscape.management.client.IStatusItem;
import com.netscape.management.client.MenuItemSeparator;
import com.netscape.management.client.MenuItemText;
import com.netscape.management.client.ResourcePage;
import com.netscape.management.client.StatusItemSecureMode;
import com.netscape.management.client.StatusItemText;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.topology.AbstractServerObject;
import com.netscape.management.client.topology.IRemovableServerObject;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.LDAPUtil;
import com.netscape.management.client.util.RemoteImage;
import com.netscape.management.client.util.UtilConsoleGlobals;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPDN;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchResults;

/**
 * Netscape Certificate Server 4.0 configuration entry point. The
 * directory server needs to contain the name of this class in order
 * for the topology view to load this class.
 *
 * @author Jack Pan-Chen
 * @author Thomas Kwan
 * @version $Revision$, $Date$
 * @date        01/12/97
 */
public class CMSAdmin extends AbstractServerObject
    implements IWizardDone, IRemovableServerObject, IMenuInfo
{

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "CMSADMIN";
    private static final String START = "start";
    private static final String STOP = "stop";
    private static final String CONFIGURE = "configure";
//    private static final String START_DAEMON_CGI = "Tasks/Operation/StartDaemon";

    private ConsoleInfo mConsoleInfo;       // global information
    private CMSServerInfo mServerInfo;      // server-specific information
    private ConsoleInfo mServerInstanceInfo;
    private CMSServerInfo mStatusInfo;      // server-specific information
    private CMSUIFramework  mFramework;     // parent frame
    private CMSPageFeeder mPagefeeder;      // what generates tab views
    //private CMSInfoPanel mInfoPanel;        // information panel
    private RemoteImage mIconImage = null;  // server icon
    private String mServerID, mServerVersion, mInstallationDate, mServerRoot;
    private String mHost = null;            // server name
    private int mPort = 0;                  // server port
    private String mAdminURL = null;        // admin server url
    private int mServerStatus = STATUS_UNKNOWN;
    private StatusItemText mAuthid;
    private JFrame mActiveFrame;

    protected ResourceBundle mResource;   //resource boundle

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSAdmin()
    {
        //Debug.setTrace(true);
        if (mActiveFrame == null)
            mActiveFrame = UtilConsoleGlobals.getActivatedFrame();
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
		// STATUS_UPDATE_INTERVAL = 1500000;
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    public int getServerLastKnownStatus() {
        return mServerStatus;
    }

    /**
     *  Initialize the page with global information.
     *
     * @param info  global information.
     */
    public void initialize(ConsoleInfo info) {
        mConsoleInfo = info;
        mIconImage = CMSAdminUtil.getImage(CMSAdminResources.IMAGE_CERTICON_SMALL);
        getInfo( info.getCurrentDN());
        //getServerStatus();
        if (info.getCurrentDN() == null) {
          Debug.println( "initialized CMSAdmin (Standalone mode)");
        } else {
          super.initialize( info );
        }
        Debug.println( "initialized CMSAdmin for " + mConsoleInfo.getCurrentDN() );
    }


    /**
     * overwrite the base class to add admin port number
     * Not sure we want to do this.
     *
    protected Vector initializeNodeDataVector(String dataKeys[]) {
        Vector v = super.initializeNodeDataVector(dataKeys);
        if ( mServerInfo != null ) {
            int port = mServerInfo.getPort();
            if ( port > 0 ) {
                String label = mResource.getString(PREFIX+"_ADMINPORT_LABEL");
                v.addElement(new NodeData("nsServerPort",
                                          label,
                                          Integer.toString(port)));
            }
        }
        return v;
    }
     */

    /**
     *  return the server instance name instead for now
     *
     * @return return the server name
     *
    */
    public String getName() {
        return ("Certificate Server ("+ mServerID +")");
    }


    /**
     * Return the information panel. - Admin take over this already
     *
     * @return information panel
     *
    public Component getCustomPanel() {
        if(mInfoPanel == null)
            mInfoPanel = new CMSInfoPanel( (IServerObject)this,
                                        mHost,
                                        mPort,
                                        mServerVersion,
                                        mInstallationDate,
                                        mAdminURL);
        return mInfoPanel;
    }
    */

    /**
     * Return connection info for a server instance.
     * @return Connection info for a server instance.
     */
    public CMSServerInfo getServerInfo() {
        return mServerInfo;
    }

    public ConsoleInfo getServerInstanceInfo() {
        mServerInstanceInfo = (ConsoleInfo)mConsoleInfo.clone();
        return mServerInstanceInfo;
    }

    /**
     * Returns the global console info.
     *
     * @return Global console info reference.
     **/
    public ConsoleInfo getConsoleInfo() {
        return mConsoleInfo;
    }

    /**
     * This function is called when the certificate server is deselected
     * on the topology view.
     */
    public void unselect(IPage viewInstance) {
//      Debug.println( "DSAdmin unselect" );
        super.unselect(viewInstance);
        fireRemoveMenuItems( viewInstance, this );
    }

    /**
     * This function is called when the directory server is selected
     * on the topology view.
     */
    public void select(IPage viewInstance) {
/*
        if (_removed)
            return;
*/

        HourGlass hglass = new HourGlass(mActiveFrame);
        super.select(viewInstance); // sets _viewInstance used
                                    // by getViewInstance()
        Debug.println( "CMSAdmin.select(): viewInstance =" +
                       getViewInstance() );
        fireAddMenuItems( viewInstance, this );
        if (mPort == 0) {
            fireDisableMenuItem(viewInstance, START);
            fireDisableMenuItem(viewInstance, STOP);
            fireEnableMenuItem(viewInstance, CONFIGURE);
        } else if ( getServerStatus() == STATUS_STARTED ) {
            fireDisableMenuItem( viewInstance, START );
            fireEnableMenuItem(viewInstance, STOP);
            fireDisableMenuItem(viewInstance, CONFIGURE);
        } else {
            fireEnableMenuItem( viewInstance, START );
            fireDisableMenuItem( viewInstance, STOP );
            fireDisableMenuItem(viewInstance, CONFIGURE);
        }
        if (hglass != null) {
            hglass.setNonWaitCursor();
            hglass = null;
        }
    }

    /**
      * Returns supported menu categories
      */
    public String[] getMenuCategoryIDs() {
        return new String[]
        {
            ResourcePage.MENU_CONTEXT,
            ResourcePage.MENU_OBJECT
        };
    }

    /**
     * Add menu items for this page.
     *
     * @param category Which menu
     */
    public IMenuItem[] getMenuItems(String category) {
        /* Same for both CONTEXT and OBJECT menus */
        return new IMenuItem[] {
            new MenuItemText( CONFIGURE,
                              CMSAdminResources.MENU_CONFIGURE_SERVER,
                              CMSAdminResources.MENU_CONFIGURE_SERVER_DESC),
            new MenuItemText( START,
                              CMSAdminResources.MENU_START_SERVER,
                              CMSAdminResources.MENU_START_SERVER_DESC),

            new MenuItemText( STOP,
                              CMSAdminResources.MENU_STOP_SERVER,
                              CMSAdminResources.MENU_STOP_SERVER_DESC),
            new MenuItemSeparator() };
    }

    /**
      * Notification that a menu item has been selected.
      */
    public void actionMenuSelected(IPage viewInstance, IMenuItem item) {
        if (item.getID().equals(START)) {
            ConsoleInfo info = getServerInstanceInfo();
            /* Fire off the Start task */
            CMSStart task = new CMSStart();
            mConsoleInfo.put(CMSStart.START_TASK_CGI, mServerID);
            mConsoleInfo.put("serverRoot",mServerRoot);
            mConsoleInfo.put("servid", mServerID);
            task.initialize(mConsoleInfo);
            //task.setConsoleInfo( info );
            boolean status = task.run( null );
            if( status ) {
                getServerStatus();
                enableStartStop(viewInstance);
            }
        } else if(item.getID().equals(STOP)) {
            CMSStop task = new CMSStop();
            ConsoleInfo info = getServerInstanceInfo();
            mConsoleInfo.put(CMSStop.STOP_TASK_CGI, mServerID);
            mConsoleInfo.put("servid", mServerID);
            mConsoleInfo.put("serverRoot",mServerRoot);
            task.initialize(mConsoleInfo);
            boolean status = task.run( null );
            if ( status ) {
                getServerStatus();
                enableStartStop(viewInstance);
            }
        } else if (item.getID().equals(CONFIGURE)) {
            startupInstallationWizard(viewInstance);
        }
    }

    public void updateMenu(IPage viewInstance) {
        getInfo(getConsoleInfo().getCurrentDN());
        if (mPort != 0) {
            fireDisableMenuItem(viewInstance, CONFIGURE);
            getServerStatus();
            enableStartStop(viewInstance);
        }
    }

    /**
     * Enable/Disable start/stop action menu.
     */
    private void enableStartStop(IPage viewInstance) {
        if (mServerStatus == STATUS_STOPPED) {
            fireEnableMenuItem( viewInstance, START );
            fireDisableMenuItem( viewInstance, STOP );
        } else if (mServerStatus == STATUS_STARTED) {
            fireEnableMenuItem( viewInstance, STOP );
            fireDisableMenuItem( viewInstance, START );
        }
    }

    /**
     * Set the title bar in the following format:<p><pre>
     *      [server information] - [server type] - [nickname]</pre>
     * Administrator id is shown at lower status bar
     */
    public void updateTitle () {
        /*
        mAuthid.setState(mResource.getString("CMSADMIN_USER_LABEL")+
            " = "+mServerInfo.getUserId()+"  ");
        mFramework.getFramework().changeStatusItemState(mAuthid);
        */
        String id = mServerID;
        int i = id.indexOf( '-' );
        if ( (i > 0) && (i < (id.length()-1)) )
            id = id.substring( i + 1 );
        mFramework.getFramework().setTitle( mServerInfo.getHost()+" - "
            + mResource.getString(CMSAdminResources.CERT_SERVER_NAME)+
            " - "+ id );
    }

    private Hashtable createWizardInfo() {
        Hashtable data = new Hashtable();
		/* This does nothing
        data.put(ConfigConstants.TASKID,TaskId.TASK_LIST_PREVIOUS_STAGES);
        data.put(ConfigConstants.OPTYPE, OpDef.OP_READ);
        data.put(ConfigConstants.PR_CERT_INSTANCE_NAME, mServerID);
        data.put(ConfigConstants.PR_SERVER_ROOT, mServerRoot);
		*/

		// moved from WIIntroPage.java
        data.put(ConfigConstants.TASKID,TaskId.TASK_GET_DEFAULT_INFO);
        data.put(ConfigConstants.OPTYPE, OpDef.OP_READ);
        data.put(ConfigConstants.PR_CERT_INSTANCE_NAME,
          mConsoleInfo.get(ConfigConstants.PR_CERT_INSTANCE_NAME));
        // #344791 - help server to make up the hostname
        data.put(ConfigConstants.PR_HOST,
          mConsoleInfo.get(ConfigConstants.PR_HOST));
        data.put(ConfigConstants.PR_SERVER_ROOT,
          mConsoleInfo.get(ConfigConstants.PR_SERVER_ROOT));
        return data;
    }

    /**
     * This is called when the installwizard is done.
     */
    public void notify(WizardWidget w) {
        Debug.println("Configuration Completed");
	for (int i = 0; i < 10; i++) { // try to detect 10 times
        	Debug.println("Check Status #" + i);
        	if ( getServerStatus() == STATUS_STARTED ) {
			return;
		}
		try {
			Thread.currentThread().sleep(2000); // 2 seconds
		} catch (Exception e) {
		}
	}
    }

    /**
     * Start up the installation wizard
     */
    public void startupInstallationWizard(IPage viewInstance) {
        Hashtable data = new Hashtable();
        CMSStartDaemon daemon = new CMSStartDaemon();
        mConsoleInfo.put("servid", mServerID);
        mConsoleInfo.put(CMSStartDaemon.START_DAEMON_CGI, mServerID);
        mConsoleInfo.put(CMSConfigCert.CONFIG_CERT_CGI, mServerID);
        daemon.initialize(mConsoleInfo);
        data.put(ConfigConstants.PR_CERT_INSTANCE_NAME, mServerID);
       	Debug.println("about to run Daemon");
        boolean success = daemon.runDaemon(data);
       	Debug.println("run daemon success = "+success);
        data.clear();
        data = null;
        boolean isInfoReady = false;

        if (success) {
            InstallWizardInfo wizardInfo =
              new InstallWizardInfo(mConsoleInfo);
            wizardInfo.setAdminFrame(mActiveFrame);
       		Debug.println("CMSAdmin: creating new configCertCgi");
            CMSConfigCert configCertCgi = new CMSConfigCert();
            configCertCgi.initialize(wizardInfo);
       		Debug.println("CMSAdmin: back from creating new configCertCgi");
            data = createWizardInfo();
            isInfoReady = configCertCgi.configCert(data);
       		Debug.println("CMSAdmin: isInfoReady = "+isInfoReady);

            if (isInfoReady) {
                JFrame frame = new JFrame();
                Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
                frame.setCursor(cursor);
                frame.invalidate();
                frame.validate();
                frame.repaint(1);
            // XXX - checking status is too slow, dont do it now.
                // InstallWizard wizard = new InstallWizard(
                //  mConsoleInfo.getFrame(), wizardInfo, this);
                InstallWizard wizard = new InstallWizard(mActiveFrame,
                  wizardInfo, null);
                wizardInfo.setAdminFrame(mActiveFrame);
                wizardInfo.put("viewInstance", viewInstance);
                wizardInfo.put("CMSAdmin", this);
                new Thread(wizard).start();
            }
        }
        data.clear();
        data = null;
        mServerStatus = STATUS_UNKNOWN;
    }

    /**
     * This function is called when the server is double clicked on
     * the topology view. Auth dialog is displayed to get user dn and pwd.
     */
    public boolean run(IPage viewInstance) {

        Debug.println("The user double click the icon "+getConsoleInfo().getCurrentDN());
        Debug.println("View instance in the run method -> "+viewInstance);

        if (getConsoleInfo().getCurrentDN() == null) {
          mServerID = (String)mConsoleInfo.get("cmsServerInstance");
        }

        mConsoleInfo.put(CMSRestart.RESTART_TASK_CGI, mServerID);
        mConsoleInfo.put(CMSStart.START_TASK_CGI, mServerID);
        mConsoleInfo.put(CMSStop.STOP_TASK_CGI, mServerID);
        mConsoleInfo.put("CMSAdmin", this);
		if (mPort == 0) {
        	getInfo(getConsoleInfo().getCurrentDN());
			if (mPort == 0) {
                startupInstallationWizard(viewInstance);
            	return false;
			}
		}

        if (getConsoleInfo().getCurrentDN() == null) {
          mHost = (String)mConsoleInfo.get("cmsHost");
          mPort = Integer.parseInt((String)mConsoleInfo.get("cmsPort"));
        } else {
          try {
            LDAPConnection ldc = mConsoleInfo.getLDAPConnection();
            if ( ldc == null ) {
                Debug.println( "No connection ready in ConsoelInfo" );
                ldc = new LDAPConnection();
                ldc.connect( mConsoleInfo.getHost(), mConsoleInfo.getPort(),
                             mConsoleInfo.getAuthenticationDN(),
                             mConsoleInfo.getAuthenticationPassword());
            }
            //Debug.println( "Fetching " + sBase + " from " +
            //               mConsoleInfo.getHost() + ":" + mConsoleInfo.getPort() );
            LDAPEntry entry = ldc.read( mConsoleInfo.getCurrentDN() );
            //Debug.println( "Got " + entry );

            try {
                String port = getAttrVal(entry, "nsserverport");

                if (port == null)
                    return false;
                else {
                    int portnum = Integer.parseInt(port);
                    if (portnum != mPort)
                        mPort = portnum;
                }
            } catch (Exception e) {
                CMSAdminUtil.showErrorDialog(mConsoleInfo.getFrame(), mResource,
                        e.toString(), CMSAdminUtil.ERROR_MESSAGE);
                return false;
            }
          } catch (LDAPException ex) {
            CMSAdminUtil.showErrorDialog(mConsoleInfo.getFrame(), mResource,
              ex.toString(), CMSAdminUtil.ERROR_MESSAGE);
          }
        }

        try {
            // server off
            if (getServerStatus() != STATUS_STARTED) {
                CMSAdminUtil.showMessageDialog(mConsoleInfo.getFrame(), mResource, PREFIX,
                    "SERVEROFF", CMSAdminUtil.ERROR_MESSAGE);
                return false;
            }

/*
            mServerInfo = new CMSServerInfo(mHost, mPort, d.getUsername(),
                d.getPassword(),
                mServerID, mInstallationDate, mServerVersion, mServerRoot);
*/
            String path = (String)mConsoleInfo.get("cmsPath");
            mServerInfo = new CMSServerInfo(mHost, mPort, "","",
                mServerID, mInstallationDate, mServerVersion, mServerRoot, path);


            String authType = mServerInfo.getAuthType();

            // server is alive, do authenticate if the server asks for
            // password-based authentication
            if (authType.equals("pwd")) {
                CMSPassword d = new CMSPassword(mActiveFrame);
                d.show();
                if (d.isCancel())
                    return false;
                mServerInfo = new CMSServerInfo(mHost, mPort, d.getUsername(),
                  d.getPassword(),
                  mServerID, mInstallationDate, mServerVersion, mServerRoot, path);
                mServerInfo.authenticate();
            }
            mConsoleInfo.put("serverInfo", mServerInfo);
        } catch (EAdminException ex) {
                CMSAdminUtil.showErrorDialog(mConsoleInfo.getFrame(), mResource,
                    ex.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
                System.exit(0); // exit if authentication fails
                return false;
        }


        //LOAD UI FRAMEWORK
        try {
            mFramework = new CMSUIFramework(mConsoleInfo, mServerInfo);
        } catch (EAdminException e) {
            CMSAdminUtil.showErrorDialog(mConsoleInfo.getFrame(), mResource,
                e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
            return false;
        }

        //show secure status
        StatusItemSecureMode statusSecureMode = new StatusItemSecureMode(Framework.STATUS_SECURE_MODE);
        statusSecureMode.setSecureMode(true);
        mFramework.getFramework().addStatusItem(statusSecureMode, IStatusItem.LEFTFIRST);
        statusSecureMode.setToolTipText(mServerInfo.getHost()+":"+mServerInfo.getPort());

        //show login status
        updateTitle ();
        return true;
    }

    /**
     * Run the object
     * @param viewInstance CMSPageFeeder object
     * @param selectionList List of selected objects
     */
    public boolean run(IPage viewInstance, IResourceObject selectionList[]) {
        return run( viewInstance );
    }

    /**
     *  perform the specified action. The command string is specified either
     *  from the content menu or the menu bar.
     *
     * @param command   Command String
     */
    public void performAction(String command) {

    }

    /**
     *  Return the server icon.
     *
     * @return The Directory Server icon.
     */
    public Icon getIcon() {
        return mIconImage;
    }

    public int getStatus() {
        return mServerStatus;
    }

    /**
     *  Return the current status of the server (running or not).
     *
     * @return The Certificate Server status.
     */
    public int getServerStatus() {
            Debug.println("Check server status");
      if (getConsoleInfo().getCurrentDN() == null) {
		return STATUS_STARTED;
      } else {
	    if ( mPort == 0) {
	      mServerStatus = STATUS_UNKNOWN;
	      return STATUS_UNKNOWN;
	    }
	    try {
	      ConsoleInfo info = getServerInstanceInfo();
	      CMSStatus task = new CMSStatus();
	      mConsoleInfo.put(CMSStatus.STATUS_TASK_CGI, mServerID);
	      mConsoleInfo.put("serverRoot",mServerRoot);
	      mConsoleInfo.put("servid", mServerID);
	      task.initialize(mConsoleInfo);
	      //task.setConsoleInfo( info );
	      boolean status = task.run( null );
	      if( status) {
		mServerStatus = STATUS_STARTED;
		return STATUS_STARTED;
	      }
	      else{
                mServerStatus = STATUS_STOPPED;
                return STATUS_STOPPED;
	      }
	    }
	    catch (Exception e) {
	      String bob = e.toString();
	      Debug.println(bob);
              if (Debug.isEnabled())
	          e.printStackTrace();
	      return STATUS_UNKNOWN;
	    }
     }
    }


  /**
   *  Return the current status of the server (running or not)
   *  by pinging the agent HTTPS port.
   *
   * @return The Certificate Server status.
   */
  public boolean getStatusFromAgentPort() {

    if (mPort == 0) {
      getInfo(getConsoleInfo().getCurrentDN());
                    if (mPort == 0) {
		      //Debug.println("CMSAdmin: getServerStatus --> "+mServerStatus);
		      return false;
		    }
    }

    //check if ssl port is functional
    try {
      if ((mServerInfo == null) || (mServerInfo.getPort() == 0)) {
            String path = (String)mConsoleInfo.get("cmsPath");
	mServerInfo = new CMSServerInfo(mHost, mPort, "", "",
					mServerID, mInstallationDate, mServerVersion, mServerRoot, path);
      }

      mServerInfo.ping();

    } catch (EAdminException e) {
      Debug.println("CMSAdmin: getServerStatus() -"+e.toString());
      if (e.getMessageString().equals(CMSAdminResources.SERVER_NORESPONSE) ||
	  e.getMessageString().equals(CMSAdminResources.SERVER_UNREACHABLE) ||
	  e.getMessageString().equals(CMSAdminResources.IOEXCEPTION) ||
	  e.getMessageString().equals(CMSAdminResources.UNKNOWNEXCEPTION) ||
	  e.getMessageString().equals(CMSAdminResources.UNKNOWNHOST) ) {
	//                mServerStatus = STATUS_STOPPED;
	return false;
      }
      Debug.println("CMSAdmin: getServerStatus() -UNKNOWN");
      //            mServerStatus = STATUS_UNKNOWN;
      return false;
    }

    Debug.println("CMSAdmin: getServerStatus() -OK");
    //        mServerStatus = STATUS_STARTED;
    return true;
  }

    /**
     * The concrete class implementing this method will clone its
     * configuration from the reference server. This supports using the
     * GET method for cloning the server.
     *
     * @param  referenceDN - DN of server to clone from.
     */
    public void cloneFrom(String referenceDN) {
        //XXX TBD
    }

    /**
     * Implements the IRemovableServerObject interface.
     * @return  true if the server was successfully removed, false otherwise
     */

    public boolean removeServer() {
        Debug.println("--------------  removeServer() ==== --------------------");

	Debug.println("getting console obj");
	ConsoleInfo info = getServerInstanceInfo();
	Debug.println("constuctor for remove");
	/* Fire off the Remove task */
	CMSRemove task = new CMSRemove();
	mConsoleInfo.put(CMSRemove.REMOVE_TASK_CGI, mServerID);
	mConsoleInfo.put("serverRoot",mServerRoot);
	mConsoleInfo.put("servid", mServerID);
	Debug.println("initalizing remove");
	task.initialize(mConsoleInfo);
	//task.setConsoleInfo( info );
	Debug.println("about to run remove rask");
	boolean status = task.run( null );
	Debug.println("remove run");
	Debug.println("Remove server status: "+ status);
	String instance = (String) mConsoleInfo.get("ServerInstance");
	if (null == instance) {
	  instance = "";
	}

	if (true == status) {  /* successfully called remove cgi */
	  Debug.println("removing topology for the server");
	  LDAPConnection ldc = mConsoleInfo.getLDAPConnection();
	  Debug.println("got the ldap connection");
	  String[] attrs = { "*", "numsubordinates" };
	  String sieDN = mConsoleInfo.getCurrentDN();
	  Debug.println("removeServer:sieDN:" + sieDN);

	  LDAPEntry sieEntry = null;
	  try {
	    sieEntry = ldc.read( sieDN, attrs );
	    Debug.println("read a ldap entry");
	  } catch (Exception ex ) {
	    Debug.println( "removeServer <" + sieDN + "> " + ex);

	    /*
	      args[1] = ex.toString();
	      DSUtil.showErrorDialog(_info.getFrame(), "removeinstance",
	      args);
	      _removed = false; // remove failed
	      */
	      return false;
	  }
	  if (sieEntry != null )	{
	    try {
	      Debug.println("Calling delete_sieTree");
	      status = delete_sieTree(sieEntry );
	    } catch (Exception ex ) {
	      Debug.println( "removeServer:Unable to delete the " +
			     "tree");
	      /*
		args[1] = ex.toString();
		DSUtil.showErrorDialog(_info.getFrame(), "removesie",
		args);
		_removed = false; // remove failed
		*/
	      return false;
	    }
	    // Now we need to remove the reference of this server
	    Debug.println("calling remove_serverinstance");
	    status = remove_serverInstance(sieDN);
	  }
	  /*
	    if ( status	 == false) {
	    args[1] = "";
	    DSUtil.showErrorDialog(_info.getFrame(), "removesie",
	    args);
	    } else {
	    DSUtil.showInformationDialog(_info.getFrame(), "121",
	    (String)null) ;
	    }

	    */
	}
	//        CMSAdminUtil.showMessageDialog(mConsoleInfo.getFrame(), mResource, PREFIX,
	//                    "NOTIMPLEMENTED", CMSAdminUtil.ERROR_MESSAGE);
        return status;
    }



  private boolean delete_sieTree (LDAPEntry entry )
    throws LDAPException {

      LDAPConnection ldc = mConsoleInfo.getLDAPConnection();
      boolean ret = false;

      String dn = entry.getDN();
      if ( entryHasChildren( entry ) ) {
	LDAPSearchResults search_results = null;
	String[] attrs = { "numsubordinates" };
	search_results = ldc.search( dn,
				     LDAPConnection.SCOPE_ONE,
				     "(objectClass=*)", attrs, false );

	while ( search_results.hasMoreElements() ) {
				/* Get the next child */
	  LDAPEntry child_entry =
	    (LDAPEntry)search_results.nextElement();
	  ret = delete_sieTree( child_entry );

	}
      }
      ldc.delete(dn);
      return true;
  }

  static boolean entryHasChildren( LDAPEntry entry ) {
    boolean hasChildren = false;
    LDAPAttribute attr = entry.getAttribute(
					    "numsubordinates" );
    if ( attr != null ) {
      Enumeration e = attr.getStringValues();
      if ( e.hasMoreElements() ) {
	String s = (String)e.nextElement();
	int count = Integer.parseInt( s );
	if ( count > 0 ) {
	  hasChildren = true;
	}
      }
    }
    return hasChildren;
  }


  private boolean remove_serverInstance (String sieDN )  {

    LDAPSearchResults search_results = null;
    String baseDN =(String)	 mConsoleInfo.get("BaseDN");
    LDAPConnection ldc = mConsoleInfo.getLDAPConnection();
    String[] attrs = { "*", "uniquemember" };
    String filter = "(&(objectclass=groupOfUniquenames)(uniquemember=" +
      sieDN+"))";

    try {
      search_results = ldc.search( baseDN, ldc.SCOPE_SUB,
				   filter, attrs, false);
    } catch (LDAPException e) {
      Debug.println( "Failed to search - " + e.toString() );
      return false;
    }
    LDAPEntry entry = null;
    while ( search_results.hasMoreElements() ) {
      // need to remove the reference to the sieDN from
      // this entry.

      entry = (LDAPEntry)search_results.nextElement();
      String eDN = entry.getDN();
      // Now we need to modify the entry to delete the
      // reference to the serevr.
      remove_intstanceFromEntry(ldc, eDN, sieDN);
    }
    return true;
  }

  private boolean remove_intstanceFromEntry ( LDAPConnection ldc,
					      String eDN, String sieDN )	{

    LDAPModificationSet mods = new LDAPModificationSet();
    LDAPAttribute attUmember = new LDAPAttribute("uniquemember", sieDN);
    Debug.println("DSAdmin:remove_intstanceFromEntry: Modifying entry:" +
		  eDN);
    mods.add( LDAPModification.DELETE, attUmember );
    try {
      ldc.modify(eDN, mods );
    } catch ( LDAPException e ) {
      Debug.println ( "Modifying " + eDN + ", " + e);
      return false;
    }
    return true;
  }

    /*==========================================================
     * private methods
     *==========================================================*/

    /**
     * Extract a single string
     *
     * @param entry A Directory entry
     * @param name Name of attribute to fetch
     * @return A concatenated string
     */
    private String getAttrVal( LDAPEntry entry, String name ) {
        LDAPAttribute findAttr =
            entry.getAttribute( name, LDAPUtil.getLDAPAttributeLocale() );
        if ( findAttr != null ) {
            return LDAPUtil.flatting(findAttr);
        }
/*
        Debug.println( "Attribute " + name + " not found in " +
            entry.getDN() );
*/
        return null;
    }

    /**
     *  get the attribute information to display in the information panel
     *
     * @param sDN   DN for the entry.
     */
    private void getInfo(String sDN) {
        //String sBase = "cn=configuration, " + sDN;
        if (sDN == null) {
        mHost = (String)mConsoleInfo.get("cmsHost");
        mPort = Integer.parseInt((String)mConsoleInfo.get("cmsPort"));
        } else {
        String sBase = sDN;
        try {
            LDAPConnection ldc = mConsoleInfo.getLDAPConnection();
            if ( ldc == null ) {
                Debug.println( "No connection ready in ConsoelInfo" );
                ldc = new LDAPConnection();
                ldc.connect( mConsoleInfo.getHost(), mConsoleInfo.getPort(),
                             mConsoleInfo.getAuthenticationDN(),
                             mConsoleInfo.getAuthenticationPassword());
            }
            //Debug.println( "Fetching " + sBase + " from " +
            //               mConsoleInfo.getHost() + ":" + mConsoleInfo.getPort() );
            LDAPEntry entry = ldc.read( sBase );
            //Debug.println( "Got " + entry );

            mHost = getAttrVal( entry, "serverHostName" );
            try {
                String port = getAttrVal(entry, "nsserverport");
                if (port == null)
                    mPort = 0;
                else
                    mPort = Integer.parseInt(port);
            } catch (Exception e) {
                mPort = 0;
            }

            // get the attribute information for display purposes
            mServerVersion = getAttrVal( entry, "serverVersionNumber" );
            mInstallationDate = getAttrVal( entry, "installationTimeStamp" );
            mServerID = getAttrVal( entry, "nsserverid" );
            mServerRoot = getAttrVal( entry, "serverroot" );
            Debug.println("CMSAdmin::PR_HOST = " + mHost);
            mConsoleInfo.put(ConfigConstants.PR_HOST, mHost);
            mConsoleInfo.put(ConfigConstants.PR_SERVER_ROOT, mServerRoot);
            mConsoleInfo.put(ConfigConstants.PR_CERT_INSTANCE_NAME, mServerID);
        } catch( Exception e) {
            Debug.println( "Fetching " + sBase + " from " +
                           mConsoleInfo.getHost() + ":" + mConsoleInfo.getPort() +
                           ", " + e );
        }

        mAdminURL = mConsoleInfo.getAdminURL();

        /* Extract the username part of the admin authentication DN */
        String[] rdns = LDAPDN.explodeDN( mConsoleInfo.getAuthenticationDN(),
                                          true );
        String s = rdns[0].trim();
        mConsoleInfo.put( "AdminUsername", s );
        //getServerStatus();
        }
    }

    /**
     * Note: it would be better if this method were declared in the superclass,
     * but having it here is better than nothing, since I need access to it
     * for getServerStatus() . . .
     */
    private IPage getViewInstance() {
        return _viewInstance;
    }

    public boolean isCloningEnabled() {
        return false;
    }

    public boolean isMigrationEnabled() {
        return false;
    }
}
