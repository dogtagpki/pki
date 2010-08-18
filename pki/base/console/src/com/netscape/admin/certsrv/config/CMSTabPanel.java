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
import com.netscape.admin.certsrv.connection.*;
import javax.swing.tree.*;
import java.awt.event.*;
import java.awt.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;

/**
 * Base Class for Tabbed right hand pane
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class CMSTabPanel extends CMSBaseConfigPanel
    implements IResourceSelectionListener, ChangeListener, IRefreshTabPanel
{
    /*==========================================================
     * variables
     *==========================================================*/
    private static String PANEL_NAME = "CMSTABPANEL";

    protected JTabbedPane mTabbedPane;          //tabbed panel
    protected JButton mbOK, mbReset, mbHelp;    //buttons
    CMSBaseResourceModel mModel;          //resource model
    private ResourceObject mParent;           //tree node parent

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSTabPanel(CMSBaseResourceModel model, ResourceObject parent) {
        this(model, parent, true);
    }

    public CMSTabPanel(CMSBaseResourceModel model, ResourceObject parent, boolean showButton) {
        super(PANEL_NAME);
        mModel = model;
        mParent = parent;

        setLayout(new BorderLayout());
        //mTabbedPane = new JTabbedPane();

        // Look and Feel
        mTabbedPane = new NSTabbedPane();
        add("Center", mTabbedPane);

		if (showButton)
		    add("South", createButtonPanel());
		mbOK.setEnabled(false);
		mbReset.setEnabled(false);

        mModel.addIResourceSelectionListener(this);
        //mTabbedPane.addChangeListener(this);
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void init() {}

    /**
     * Retrieve Resource Model
     */
    public CMSBaseResourceModel getResourceModel() {
        return mModel;
    }

    public ResourceObject getResourceObject() {
        return mParent;
    }

    /**
     * Set the Tab associated with this component dirty
     */
    public void setDirtyTab(CMSBaseTab component) {
        int index = mTabbedPane.indexOfComponent(component);
        if (index == -1) {
            Debug.println("CMSTabPanel: setDirtyTab() - component not part of this panel");
            return;
        }
        if ((mTabbedPane != null) && (mTabbedPane.getIconAt(index)== null) ) {
            mTabbedPane.setIconAt(index,
                        CMSAdminUtil.getImage(CMSAdminResources.IMAGE_DIRTY_TAB));
            mTabbedPane.repaint();
        }
        mbOK.setEnabled(true);
        mbReset.setEnabled(true);
    }

    /**
     * Clear the Tab associated with this component
     */
    public void clearDirtyTab(CMSBaseTab component) {
        int index = mTabbedPane.indexOfComponent(component);
        if (index == -1) {
            Debug.println("CMSTabPanel: clearDirtyTab() - component not part of this panel");
            return;
        }
        if ((mTabbedPane != null) && (mTabbedPane.getIconAt(index)!= null) ) {
            mTabbedPane.setIconAt(index, null);
            mTabbedPane.repaint();
        }
        setOKCancel();
    }

    //=== Callback methods ====
    public boolean applyCallback(){
        int currentTab = mTabbedPane.getSelectedIndex();
        int nTabs = mTabbedPane.getTabCount();
        boolean failed = false;

        //we will go through each tab and apply
        for (int i= 0; i < nTabs; ++i) {
            CMSBaseTab p = (CMSBaseTab)mTabbedPane.getComponentAt(i);
            if (p.isDirty()) {
                mTabbedPane.setSelectedIndex(i);
                if (!p.applyCallback()) {
                    failed = true;
                }
            }
        }

        //one or more panel falied
        if (failed) {
            //get first dirty tab
            for (int i= 0; i < nTabs; ++i) {
                CMSBaseTab p = (CMSBaseTab)mTabbedPane.getComponentAt(i);
                if (p.isDirty()) {
                    mTabbedPane.setSelectedIndex(i);
                    break;
                }
            }
            return false;
        }

        //everything ok
        if (currentTab >=0 )
            mTabbedPane.setSelectedIndex(currentTab);
        mbOK.setEnabled(false);
        mbReset.setEnabled(false);
        mbHelp.requestFocusInWindow();
        return true;
    }

    public boolean resetCallback() {
        int nTabs = mTabbedPane.getTabCount();
        for (int i= 0; i < nTabs; ++i) {
            CMSBaseTab p = (CMSBaseTab)mTabbedPane.getComponentAt(i);
            if (p.isDirty()) {
                p.resetCallback();
            }
        }
        mbOK.setEnabled(false);
        mbReset.setEnabled(false);
        return true;
    }

    public void setOKCancel() {
        int nTabs = mTabbedPane.getTabCount();
        for (int i= 0; i < nTabs; ++i) {
            CMSBaseTab p = (CMSBaseTab)mTabbedPane.getComponentAt(i);
            if (p.isDirty()) {
                return;
            }
        }
        mbOK.setEnabled(false);
        mbReset.setEnabled(false);
    }

    public void helpCallback() {
        CMSBaseTab p = (CMSBaseTab)mTabbedPane.getSelectedComponent();
        if (p != null)
            p.helpCallback();
        Debug.println("CMSTabPanel: helpCallback()");
    }

    public CMSBasePanel getSelectedTab() {
        return (CMSBasePanel)mTabbedPane.getSelectedComponent();
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/
    //== ACTIONLISTENER =====
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mbOK)) {
            applyCallback();
        }
        if (e.getSource().equals(mbReset)) {
            resetCallback();
        }
        if (e.getSource().equals(mbHelp)) {
            helpCallback();
        }
    }

    //== IResourceListener ===
    public void select(IResourceObject parent, Object viewInstance) {
        //System.out.println("CMSTabPanel: select() "+ parent);
        if (parent == mParent) {
            try {
                mTabbedPane.addChangeListener(this);
                mTabbedPane.setSelectedIndex(0);
                CMSBaseConfigPanel selectedPanel = (CMSBaseConfigPanel) mTabbedPane.getComponentAt(0);
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
        //System.out.println("CMSTabPanel: unselect() "+ parent);

        // XXX NOT SAVED MODEL IS MOVED TO HIGHER LEVEL

        //check if any tab is dirty
        boolean dirty = false;
        int nTabs = mTabbedPane.getTabCount();
        for (int i= 0; i < nTabs; ++i) {
            CMSBaseTab p = (CMSBaseTab)mTabbedPane.getComponentAt(i);
            if (p.isDirty()) {
                dirty = true;
            }
        }
        if (!dirty)
            return true;

        //return to previous node
        TreePath thisPath = new TreePath(((ResourceObject)parent).getPath());
        TreePath selectedPath =
                ((CMSResourcePage)viewInstance).getTree().getSelectionPath();
        if (!thisPath.equals(selectedPath))
        	    ((CMSResourcePage)viewInstance).getTree().setSelectionPath(thisPath);

        //popup dialog for user to set changes
        int result = showConfirmDialog("NOTSAVED");
        switch (result) {
            case JOptionPane.YES_OPTION:
                if (applyCallback()) {
                    ((CMSResourcePage)viewInstance).getTree().setSelectionPath(selectedPath);
                    return true;
                }
                break;
            case JOptionPane.NO_OPTION:
                resetCallback();
                ((CMSResourcePage)viewInstance).getTree().setSelectionPath(selectedPath);
                return true;
            default:
                break;
        }

        //can not be unselected
        return false;
    }

    //== ChangeListener ==
	public void stateChanged(ChangeEvent e) {
	    //Debug.println("CMSTabPanel: stateChanged()");
		CMSBaseConfigPanel selectedPanel = (CMSBaseConfigPanel)mTabbedPane.getSelectedComponent();
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
    public void addTab(CMSBaseTab p) {
		mTabbedPane.addTab(p.getTitle(),  p);
	}

    /*==========================================================
	 * protected methods
     *==========================================================*/

    /**
     * create button panel using the factory method
     */
    protected JPanel createButtonPanel() {
        mbOK = makeJButton("APPLY");
		mbReset = makeJButton("RESET");
		mbHelp = makeJButton("HELP");

		JButton[] buttons = { mbOK, mbReset, mbHelp };
		return makeJButtonPanel(buttons, true, true);
    }

    class NSTabbedPane extends JTabbedPane {
/*
		public String getUIClassID() {
			return "SecondaryTabbedPaneUI";
		}
*/
	}

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

    protected void showErrorDialog(String message) {
        CMSAdminUtil.showErrorDialog(mModel.getFrame(), mResource, message, ERROR_MESSAGE);
    }


}
