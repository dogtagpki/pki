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

import javax.swing.*;
import javax.swing.tree.*;
import javax.swing.event.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;

/**
 * This page creates the resource view
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv
 */
public class CMSResourcePage extends ResourcePage implements Cloneable {

    /*==========================================================
     * variables
     *==========================================================*/
    protected IMenuInfo mMenuInfo;          // menu information delegation

	/*==========================================================
     * constructors
     *==========================================================*/

    /**
     * Return ResourcePage using the data model specified.
     */
	public CMSResourcePage(CMSBaseResourceModel resourceModel) {
		super(resourceModel);
		resourceModel.setResourcePage(this);
		//we will only support single selection model
		TreeSelectionModel selectionModel = _tree.getSelectionModel();
		selectionModel.setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION );
	}

    /*==========================================================
	 * public methods
     *==========================================================*/

	/**
	 * Need to overwrite this one to clone
	 * DSResourcePage instead of ResourcePage
	 * @return copy of resource page
	 */
    public Object clone() {
		CMSResourcePage rp = new CMSResourcePage((CMSBaseResourceModel)_model);
		rp.setCellRenderer( _treeRenderer );
		rp.setPageTitle(getPageTitle());
	    rp.setMenuInfo(mMenuInfo);
		return rp;
	}

	/**
     * Retrieve JTree Obejct
     * @return JTree obejct in the resource page
     */
    public JTree getTree() {
        return (JTree)_tree;
    }

    /**
     * Implements TreeSelectionListener.  Called when an object is selected
	 * in the resource tree.  Informs IResourceModelListeners of this event.
     */
	public void valueChanged(TreeSelectionEvent ev)
	{
		IResourceObject[] selection = getSelection();
		if(selection != null) {
			if(selection.length == 1) // single selection {
				setCustomPanel(_model.getCustomPanel(this, selection[0]));
		}
		_model.actionObjectSelected(this, selection, getPreviousSelection());

		//the selected node not necessary the original selection
		//in case of not allow to change
		_previousSelection = getSelection();
	}

    /**
     * Called internally when page is unselected
     */
	public void pageUnselected(IFramework framework) {
        super.pageUnselected(framework);
        //check if the data is not saved
	}

	/**
	 *	Initializes page.  Called after construction or after clonePage().
	 *  The reference to IFramework allows this page to set menu items, status
	 *  bars, and add event notification listeners. COVERWRITES the method in
	 *  the ResourcePage class to provide the menu contain separartion.
	 */
	public void initialize(IFramework framework) {
	    //Debug.println("CMSResourcePage - initialize() "+mMenuInfo);
	    super.initialize(framework);
	    if (mMenuInfo != null)
	        addMenuItems(mMenuInfo , _menuInfoAction);
	}

	/**
     * Set and replace the existing menuInfo delegation object
     */
    public void setMenuInfo(IMenuInfo menuInfo) {
        //Debug.println("CMSResourcePage - setMenuInfo() "+menuInfo);
        mMenuInfo = menuInfo;
    }

    /**
     * Retrieve IMenuInfo object
     */
    public IMenuInfo getMenuInfo() {
        if (mMenuInfo == null) {
            mMenuInfo = new CMSBaseMenuInfo();
        }
        return mMenuInfo;
    }

	/**
	 * Start the zipping status bar
	 */
    public void progressStart() {
        //XXX COMEBACK AFTER UPGRADE
        _statusItemProgress.start();
    }

    /**
     * Stop the zipping status bar
     */
    public void progressStop() {
        //XXX COMEBACK AFTER UPGRADE
        _statusItemProgress.stop();
    }

}

