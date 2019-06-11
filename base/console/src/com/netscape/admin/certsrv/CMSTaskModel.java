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

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;

import com.netscape.admin.certsrv.security.CertManagementDialog;
import com.netscape.admin.certsrv.security.KeyCertWizard;
import com.netscape.admin.certsrv.security.PKCS11ManagementDialog;
import com.netscape.management.client.Framework;
import com.netscape.management.client.IMenuInfo;
import com.netscape.management.client.IMenuItem;
import com.netscape.management.client.IPage;
import com.netscape.management.client.ITaskObject;
import com.netscape.management.client.MenuItemSeparator;
import com.netscape.management.client.TaskModel;
import com.netscape.management.client.TaskObject;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.preferences.PreferenceManager;
import com.netscape.management.client.preferences.Preferences;
import com.netscape.management.client.util.ClassLoaderUtil;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.LDAPUtil;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPDN;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;

/**
 * Certificate Server 4.0 Task Model
 *
 * @author Jack Pan-Chen
 * @author Thomas Kwan
 * @version $Revision$, $Date$
 * @date	 	02/04/97
 */
public class CMSTaskModel extends TaskModel implements IMenuInfo {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFERENCES_TASK_TAB = "TaskTab";
    private static final String PREFERENCES_TASK_LIST = "TaskList";

    static public String MENU_KEYCERT = CMSAdminResources.MENU_KEYCERT;
    static public String MENU_KEYCERT_MANAGEMENT =
                            CMSAdminResources.MENU_KEYCERT_MANAGEMENT;
    static public String MENU_PKCS11 = CMSAdminResources.MENU_PKCS11;
    static public String REF_TASKMODEL = "CMSTASKMODEL";

    protected ITaskObject mSelection;
    private ConsoleInfo mConsoleInfo;
    private CMSServerInfo mServerInfo = null;

	/*==========================================================
     * constructors
     *==========================================================*/

    public CMSTaskModel(ConsoleInfo ci, CMSServerInfo serverInfo) {
		mServerInfo = serverInfo;
        mConsoleInfo = ci;
        init();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * getServerInfo()
     */
    public CMSServerInfo getServerInfo() {
        return mServerInfo;
    }

    /**
     * Returns supported menu categories
     */
    public String[] getMenuCategoryIDs() {
        return new String[] {
            Framework.MENU_FILE
        };
    }

    /**
     * add menu items for this page.
     */
    public IMenuItem[] getMenuItems(String categoryID) {
        if(categoryID.equals(Framework.MENU_FILE)) {
            return new IMenuItem[] {
                //getMenuItemText(MENU_KEYCERT),
                //getMenuItemText(MENU_KEYCERT_MANAGEMENT),
               // getMenuItemText(MENU_PKCS11),
                new MenuItemSeparator()
            };
        }
        return null;
    }

    public void actionObjectSelected(IPage viewInstance,
                                ITaskObject selection,
                                ITaskObject previousSelection) {
        super.actionObjectSelected(viewInstance, selection, previousSelection);
        mSelection = selection;
    }

    /**
     * Notification that a menu item has been selected.
     */
    public void actionMenuSelected(IPage viewInstance, IMenuItem item) {

        if(item.getID().equals(MENU_KEYCERT)) {
            new KeyCertWizard(mConsoleInfo);
        } else if(item.getID().equals(MENU_KEYCERT_MANAGEMENT)) {
            (new CertManagementDialog( mConsoleInfo )).showModal();
        } else if(item.getID().equals(MENU_PKCS11)){
            (new PKCS11ManagementDialog( mConsoleInfo )).showModal();
        }
    }

    /*==========================================================
	 * private methods
     *==========================================================*/

    private void init() {
		TaskObject root = new TaskObject( "root", mConsoleInfo );
		root.setAllowsChildren(true);
		String serverDN = mConsoleInfo.getCurrentDN();
		if ( serverDN != null ) {
			/* Check if there is a list of tasks */
			String order = findTaskOrder( serverDN );

			/* Accumulate tasks in a hash table */
			Hashtable<String, TaskObject> list = new Hashtable<>();
			Debug.println( "CMSTaskModel.init: Searching for tasks under " +
						   serverDN );
			findTasks(root, serverDN, list );
			/* Need to go up one from the instance entry, to get non-instance-
			   specific task entries. */
			serverDN = "cn=Tasks," +
				new netscape.ldap.util.DN(
					mConsoleInfo.getCurrentDN() ).getParent().toString();
			Debug.println( "CMSTaskModel.init: Searching for tasks under " +
						   serverDN );
			findTasks(root, serverDN, list );

			/* Now sort them by preferred order, or just list them as found */
			if ( order != null ) {
				StringTokenizer st = new StringTokenizer( order, " " );
				while( st.hasMoreTokens() ) {
					TaskObject task = list.get( st.nextToken() );
					if ( task != null ) {
						root.add(task);
					}
				}
			} else {
				Enumeration<TaskObject> en = list.elements();
				while( en.hasMoreElements() ) {
					root.add( en.nextElement() );
				}
			}
		} else {
			Debug.println( "CMSTaskModel.init: no currentDN" );
		}
		setRoot(root);
	}

    private void findTasks(TaskObject root, String base, Hashtable<String, TaskObject> list ) {
		// connect to the DS and search for task information
		LDAPConnection ldc = mConsoleInfo.getLDAPConnection();
		if ( ldc == null)
			return;
		try {
			String[] attrs = {"nsclassname", "nsexecref"};
			LDAPSearchResults result =
				ldc.search( base, LDAPConnection.SCOPE_SUB,
							"(objectclass=nstask)",
							attrs, false );

			while ( result.hasMoreElements() ) {
				String sJavaClassName = null;
				LDAPEntry findEntry = (LDAPEntry)result.nextElement();
				Debug.println( "Found task " + findEntry.getDN() );
				LDAPAttribute anAttr =
					findEntry.getAttribute( attrs[0] );
				if ( anAttr != null )
					sJavaClassName =
						LDAPUtil.flatting( anAttr.getStringValues() );
				if ( sJavaClassName != null ) {
					// load the associated task class file
					try {
						Class<?> c =
							ClassLoaderUtil.getClass(mConsoleInfo,
													 sJavaClassName);
						TaskObject task = (TaskObject)c.newInstance();
						ConsoleInfo taskConsoleInfo =
							(ConsoleInfo)mConsoleInfo.clone();
						taskConsoleInfo.setCurrentDN(findEntry.getDN());
						/* Add a listener interface for
						   authentication changes */
						anAttr = findEntry.getAttribute( attrs[1] );
						if ( anAttr != null ) {
							String s = LDAPUtil.flatting(
								anAttr.getStringValues() );
							taskConsoleInfo.put( "execref", s );
						}
						taskConsoleInfo.put(REF_TASKMODEL, this );
						task.setConsoleInfo(taskConsoleInfo);
						Debug.println( "CMSSTaskModel.init: Found task " +
									   task );
						String[] rdns =
							LDAPDN.explodeDN( findEntry.getDN(), true );
						list.put( rdns[0], task );
					} catch (Exception e) {
						Debug.println("CMSTaskModel.findTasks: could not " +
									  "load class: " + sJavaClassName + ", " +
									  e);
						// This implicitly means that this task should
						// not show up in
						// in the Task list.
					}
				}
			}
		} catch ( LDAPException e ) {
			Debug.println( "CMSTaskModel.findTasks: " + e.toString() );
		}
	}

    //get task orders
    private String findTaskOrder( String base ) {
		String order = null;
		/* See if there is a personal preference set */
		PreferenceManager pm =
			PreferenceManager.getPreferenceManager(Framework.IDENTIFIER,
												   Framework.VERSION);
		Preferences p = pm.getPreferences(PREFERENCES_TASK_TAB);
		if ( p != null ) {
			order = p.getString( PREFERENCES_TASK_LIST );
			if ( (order != null) && (order.trim().length() > 0) ) {
				return order;
			} else {
				order = null;
			}
		}

		LDAPConnection ldc = mConsoleInfo.getLDAPConnection();
		if ( ldc == null ) {
			return null;
		}
		/* Check if there is a list */
		try {
			String dn = "cn=task summary, cn=Operation, cn=Tasks," + base;
			String[] attrs = {"description"};
			LDAPEntry entry = ldc.read( dn, attrs );
			if ( entry != null ) {
				LDAPAttribute attr = entry.getAttribute( attrs[0] );
				if ( attr != null ) {
					order = attr.getStringValues().nextElement();
				}
			}
		} catch ( LDAPException ex ) {
			Debug.println( "CMSTaskModel.findTaskOrder: no list of tasks, " +
						   ex );
		}
		return order;
	}

}
