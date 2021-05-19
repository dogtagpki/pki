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

import java.awt.Component;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.ResourceBundle;
import java.util.Vector;

import javax.swing.JFrame;

import com.netscape.admin.certsrv.config.CMSBlankPanel;
import com.netscape.admin.certsrv.menu.RefreshTabPane;
import com.netscape.management.client.IPage;
import com.netscape.management.client.IResourceObject;
import com.netscape.management.client.ResourceModel;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.UtilConsoleGlobals;

/**
 *	Netscape Certificate Server 4.0 BASE resource model.<br>
 *
 *  This class represtents the tree node objects displayed
 *  in the right tree-view.<p>
 *
 *  Menu Event are now handled by extenal IMenuInfo object.
 *
 * @author Jack Pan-Chen
 * @author Thomas Kwan
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv
 */
public class CMSBaseResourceModel extends ResourceModel {

    /*==========================================================
     * variables
     *==========================================================*/

    private CMSResourcePage mPage;          // physical page representation
	protected ConsoleInfo mConsoleInfo;     // console info
	protected CMSServerInfo mServerInfo;    // server info
	protected IResourceObject[] mSelection; // selected objects
	protected Vector<IResourceSelectionListener> mSelectionListeners;   // listener list
	protected ResourceBundle mResource;     // resource boundle
	protected Hashtable<String, CMSResourceObject> mNickNameRegistry;  // storing the object nickname pair
    protected RefreshTabPane mRefreshPane;

	/*==========================================================
	 * constructors
	 *==========================================================*/

	/**
	 * Constructor - create all panels.
	 *
	 * @param info	Global console connection information
	 * @param serverInfo Server instance connection information
	 */
	public CMSBaseResourceModel( ConsoleInfo info, CMSServerInfo serverInfo ) {
		mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
		mConsoleInfo = info;
		mServerInfo = serverInfo;
		mNickNameRegistry = new Hashtable<>();
		mSelectionListeners = new Vector<>();
		init();
	}

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Set the physical page associated with this model
     * @param page CMSResourcePage instance
     */
    public void setResourcePage(CMSResourcePage page) {
        mPage = page;
    }

    public CMSResourcePage getResourcePage() {
        return mPage;
    }

    /**
     * Return the global console information reference.
     *
     * @return The global console information reference.
     **/
    public ConsoleInfo getConsoleInfo() {
		return mConsoleInfo;
    }

    /**
     * Return the Server information reference.
     *
     * @return The server information reference.
     **/
    public CMSServerInfo getServerInfo() {
		return mServerInfo;
    }


    /**
     * Get Parent Frame
     * @return frame to be usd in dialogs
     */
    public JFrame getFrame() {
        return UtilConsoleGlobals.getActivatedFrame();
    }

    /**
     * Tree Nodes selected call back
     */
	@Override
    public void actionObjectSelected( IPage viewInstance,
									  IResourceObject[] selection,
									  IResourceObject[] previousSelection) {

		//Debug.println("CMSResourceModel: actionObjectSelected()");
		mSelection = selection;
		if ( mSelection == null )
			mSelection = new IResourceObject[0];
		Vector<Component> selected = new Vector<>();
		Vector<IResourceObject> toNotify = new Vector<>();
		/* Signal all selected objects, keep track of which ones */
		for( int i = 0; i < mSelection.length; i++ ) {
		    IResourceObject sel = mSelection[i];
		    Component c = sel.getCustomPanel();
            if (mRefreshPane != null) {
                mRefreshPane.select(c);
            }
		    if ( (c != null) && (mSelectionListeners.indexOf( c ) >= 0) ) {
				toNotify.addElement( sel );
    		}
   			selected.addElement( c );
		}

		/* All other listeners must be unselected */
		boolean canMove = true;
		if ( previousSelection != null ) {
    		for( int i = 0; i < previousSelection.length; i++ ) {
	    	    IResourceObject sel = previousSelection[i];
    		    Component c = sel.getCustomPanel();
    		    if ( (mSelectionListeners.indexOf( c ) >= 0) &&
		             (selected.indexOf( c ) < 0) ) {
		            try {
            			IResourceSelectionListener l =
               			    (IResourceSelectionListener)c;
        	    		if (!l.unselect( sel, viewInstance ))
        	    		    canMove = false;
        	    	} catch ( Exception e ) {
        	    	    //System.err.println( e );
        	    	    Debug.println( e.toString() );
        	    	}
        		}
    		}
    	}

        if (!canMove)
            return;

		for( int i = 0; i < toNotify.size(); i++ ) {
		    IResourceObject sel =
				toNotify.elementAt( i );
		    Component c = sel.getCustomPanel();
			IResourceSelectionListener l =
				(IResourceSelectionListener)c;
			l.select( sel, viewInstance );
		}

		//change menu
		super.actionObjectSelected(viewInstance, selection, previousSelection);
	}

    public void setRefreshCallback(RefreshTabPane pane) {
        mRefreshPane = pane;
    }

    /**
      * Adds a listener that is interested in receiving selection events.
	  * Called by panels
      */
	public void addIResourceSelectionListener(IResourceSelectionListener l) {
		mSelectionListeners.addElement(l);
	}

    /**
      * Removes previously added IDSResourceSelectionListener.
	  * Called by panels
      */
	public void removeIResourceSelectionListener(IResourceSelectionListener l) {
		mSelectionListeners.removeElement(l);
    }

	/**
     *   Returns list of listeners for this model.
	 */
	public Enumeration<IResourceSelectionListener> getSelectionListeners() {
		return mSelectionListeners.elements();
	}

    /**
     * The SubSystemUILoader should use this function to add
     * subsystem node into the root node. SubSystemLoader is responsible
     * for setting up the subtrees.
     */
    public void addSubSystemNode(CMSResourceObject node) {
        ((CMSResourceObject)getRoot()).add(node);
    }

    /**
     * Register the nick name of the resource object, so other sub system
     * can look up and retrieve the corresponding resource object.
     */
    public void registerNickName(String nickName, CMSResourceObject node) {
        mNickNameRegistry.put(nickName, node);
    }

    /**
     * Retrieve the resource obejct associated with this nickname
     */
    public CMSResourceObject getByNickName(String nickName) {
        return mNickNameRegistry.get(nickName);
    }

	/**
	 * Start the zipping status bar
	 */
    public void progressStart() {
        mPage.progressStart();
    }

    /**
     * Stop the zipping status bar
     */
    public void progressStop() {
        mPage.progressStop();
    }

    /*==========================================================
	 * priotected methods
     *==========================================================*/

    protected void init() {
        CMSResourceObject root = new CMSResourceObject();
		root.setName(mResource.getString(CMSAdminResources.CERT_SERVER_NAME)+":" + mServerInfo.getPort());
		root.setCustomPanel( new CMSBlankPanel(this));
		root.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_CERTICON_SMALL));
		root.setAllowsChildren(true);
		super.setRoot( root );
    }

}
