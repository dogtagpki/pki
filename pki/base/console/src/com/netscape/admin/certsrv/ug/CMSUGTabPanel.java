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
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import javax.swing.tree.*;
import java.awt.event.*;
import java.awt.*;

/**
 * Base Class for Tabbed right hand pane
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class CMSUGTabPanel extends CMSBasePanel
    implements IResourceSelectionListener, ChangeListener,
    IRefreshTabPanel
{
    /*==========================================================
     * variables
     *==========================================================*/
    private static String PANEL_NAME = "CMSUGTABPANEL";

    protected JTabbedPane mTabbedPane;     //tabbed panel
    protected CMSBaseResourceModel mModel; //resource model
    protected ResourceObject mParent;      //tree node parent

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSUGTabPanel(CMSBaseResourceModel model, ResourceObject parent) {
        super(PANEL_NAME);
        mModel = model;
        mParent = parent;
        mModel.addIResourceSelectionListener(this);

        setLayout(new BorderLayout());
        // Look and Feel
        mTabbedPane = new NSTabbedPane();
        add("Center", mTabbedPane);
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Retrieve Resource Model
     */
    public CMSBaseResourceModel getResourceModel() {
        return mModel;
    }

    //== IResourceListener ===

    public void select(IResourceObject parent, Object viewInstance) {
        //System.out.println("CMSTabPanel: select() "+ parent);
        if (parent == mParent) {
            try {
                mTabbedPane.addChangeListener(this);
                mTabbedPane.setSelectedIndex(0);
                CMSBaseUGTab selectedPanel = (CMSBaseUGTab) mTabbedPane.getComponentAt(0);
                if ( selectedPanel != null )
                    selectedPanel.initialize();
                mTabbedPane.invalidate();
                mTabbedPane.validate();
            } catch (ArrayIndexOutOfBoundsException e) {
                //NO TAB SO IGNORE
            }
        }
    }

    public boolean unselect(IResourceObject parent, Object viewInstance) {
        return true;
    }

    public CMSBasePanel getSelectedTab() {
        //Debug.println("CMSUGTabPanel: getSelectedTab()");
        return (CMSBasePanel)mTabbedPane.getSelectedComponent();
    }

    //== ChangeListener ==
	public void stateChanged(ChangeEvent e) {
	    //Debug.println("CMSTabPanel: stateChanged()");
		CMSBaseUGTab selectedPanel = (CMSBaseUGTab)mTabbedPane.getSelectedComponent();
        if ( selectedPanel != null )
            selectedPanel.initialize();
        mTabbedPane.invalidate();
        mTabbedPane.validate();
        mTabbedPane.repaint(1);
	}

    /**
     * Add Panels to the Tab Panel. ChangeListener is
     * added automatically.
     *
     * @param p CMS Panel to be added
     */
    public void addTab(CMSBaseUGTab p) {
		mTabbedPane.addTab(p.getTitle(),  p);
	}

    /*==========================================================
	 * protected methods
     *==========================================================*/

    //look and feel
    class NSTabbedPane extends JTabbedPane {
/*
		public String getUIClassID() {
			return "SecondaryTabbedPaneUI";
		}
*/
	}

}
