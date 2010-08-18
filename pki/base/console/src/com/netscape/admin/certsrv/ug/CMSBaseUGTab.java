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
package com.netscape.admin.certsrv.ug;

import com.netscape.admin.certsrv.*;
import java.util.*;
import java.awt.event.*;
import java.awt.*;
import javax.swing.*;
import javax.swing.border.*;

/**
 * Base class for the tabs in the User and group tabbed pane.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public abstract class CMSBaseUGTab  extends CMSBasePanel
    implements MouseListener, IRefreshTab
{

    /*==========================================================
     * variables
     *==========================================================*/
    protected CMSBaseResourceModel mModel; //resource model

    private String mTitle;                  // panel title actually shows
    protected boolean mInit = false;        // true if this panel is initialized
    protected JPanel mListPanel, mActionPanel;  //panels
    protected String mHelpToken;

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSBaseUGTab(String panelName, CMSBaseResourceModel model) {
        super(panelName);
        mModel = model;
        try {
            String title = mResource.getString(mPanelName+"_TITLE");
            mTitle = title;
        } catch (MissingResourceException e) {
            mTitle = "Missing Title";
        }
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Initialization of the panel. Subcalss must provide
     * the proper implementation.
     */
    public void init() {
        setLayout(new BorderLayout());

        //======== list panel ========================
		mListPanel = createListPanel();
		mListPanel.setBorder(new EmptyBorder(DIFFERENT_COMPONENT_SPACE,
		        DIFFERENT_COMPONENT_SPACE,
		        DIFFERENT_COMPONENT_SPACE - COMPONENT_SPACE,
		        DIFFERENT_COMPONENT_SPACE));
		add("Center",mListPanel);

		//====== action panel ===========================
		mActionPanel = createActionPanel();
		add("South",mActionPanel);
    }

    /**
     * Called by the Tab parent to initialize the panel
     */
    public void initialize() {
        if (!mInit) {
            init();
            mInit = true;
        }
    }


    /**
     * Returns the title of the tab
     * @return string representation of the title
     */
    public String getTitle() {
		return mTitle;
	}

	/**
     * set the title of the tab
     */
    public void setTitle(String title) {
		mTitle = title;
	}

    public void helpCallback() {
        CMSAdminUtil.help(mHelpToken);
    }

    public void mousePressed(MouseEvent e) {}
    public void mouseReleased(MouseEvent e) {}
    public void mouseEntered(MouseEvent e) {}
    public void mouseExited(MouseEvent e) {}

    /*==========================================================
	 * protected methods
     *==========================================================*/
    protected abstract JPanel createActionPanel();
    protected abstract JPanel createListPanel();

    //=== OVERWRITE DIALOG MESSAGE =====================

    protected void showMessageDialog(String keyword, int messageType ) {
        CMSAdminUtil.showMessageDialog(mModel.getFrame(), mResource, mPanelName, keyword, messageType);
    }

    protected void showMessageDialog(String keyword) {
        showMessageDialog(keyword, ERROR_MESSAGE);
    }

    protected int showConfirmDialog(String keyword, int messageType ) {
        return CMSAdminUtil.showConfirmDialog(mModel.getFrame(), mResource, mPanelName, keyword, messageType);
    }

    protected int showConfirmDialog(String keyword) {
        return showConfirmDialog(keyword, WARNING_MESSAGE);
    }

    protected int showConfirmDialog(String keyword, String[] params) {
        return showConfirmDialog(keyword, params, WARNING_MESSAGE);
    }

    protected void showErrorDialog(String message) {
        CMSAdminUtil.showErrorDialog(mModel.getFrame(), mResource, message, ERROR_MESSAGE);
    }

    public abstract void refresh();
}
