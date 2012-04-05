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
package com.netscape.admin.certsrv.config;

import com.netscape.admin.certsrv.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import javax.swing.text.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;
import java.util.*;
import java.awt.*;
import java.awt.event.*;

/**
 * Netscape Certificate Server 4.0 Default Base Panel
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public abstract class CMSBaseConfigPanel extends CMSBasePanel {

    /*==========================================================
     * variables
     *==========================================================*/

    private String mTitle;                  // panel title actually shows
    protected boolean mDirty = false;       // panel dirty flag
    protected boolean mInit = false;        // true if this panel is initialized
    protected JPanel mCenterPanel;          // display panel
    protected String mHelpToken;

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSBaseConfigPanel(String panelName) {
        super(panelName);
        //mPanelName = panelName;
        setLayout(new BorderLayout());
        mCenterPanel = new JPanel();
        try {
            String title = mResource.getString(mPanelName+"_TITLE");
            mTitle = title;
        } catch (MissingResourceException e) {
            mTitle = "Missing Title";
        }
    }

    public CMSBaseConfigPanel() {
        super("");
        mTitle = "Missing Title";
    }

    /*==========================================================
	 * abstract methods
     *==========================================================*/

    //Actual Instanciation of the panels
    public abstract void init();

    //Implementation for saving panel information
    public abstract boolean applyCallback();

    //Implementation for reset values
    public abstract boolean resetCallback();


    /*==========================================================
	 * public methods
     *==========================================================*/

    //Implementation for calling help
    public void helpCallback() {
        CMSAdminUtil.help(mHelpToken);
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

	/**
     * see if the contents of the panel have been changed but not applied
     * @return true if dirty; otherwise,false.
     */
    public boolean isDirty() {
        return mDirty;
    }

    /**
     * Called by the Tab parent to initialize the panel
     */
    public void initialize() {
        if (!mInit) {
            //Debug.println("CMSBasePanel: initialize()"+mPanelName);
            mCenterPanel.setBorder(new EmptyBorder(DEFAULT_CENTER_INSETS));
            init();
            mInit = true;
        }
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent e) {
        if (mInit)
            this.setDirtyFlag();
    }

    //== DocumentListener ==
    public void insertUpdate(DocumentEvent e) {
        if (mInit)
            this.setDirtyFlag();
    }
    public void removeUpdate(DocumentEvent e){
        if (mInit)
            this.setDirtyFlag();
    }
    public void changedUpdate(DocumentEvent e){
        if (mInit)
            this.setDirtyFlag();
    }

    //== ItemListener ==
    public void itemStateChanged(ItemEvent e){
        if (mInit)
            this.setDirtyFlag();
    }

    //== ListSelectionListener ==
    public void valueChanged(ListSelectionEvent e){
        if (mInit)
            this.setDirtyFlag();
    }

    /*==========================================================
	 * protected methods
     *==========================================================*/

    //=== Dirty Flag =========================

    //set dirty flag
    protected void setDirtyFlag() {
        mDirty = true;
    }

    //clear dirty flag
    protected void clearDirtyFlag() {
        mDirty = false;
    }

}
