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
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.SwingConstants;

import com.netscape.management.client.Framework;
import com.netscape.management.client.IFramework;
import com.netscape.management.client.IResourceModel;
import com.netscape.management.client.IStatusItem;
import com.netscape.management.client.MenuItemText;
import com.netscape.management.client.ResourceModel;
import com.netscape.management.client.ResourceObject;
import com.netscape.management.client.ResourcePage;
import com.netscape.management.client.StatusItemSecureMode;
import com.netscape.management.client.StatusItemSpacer;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.topology.customview.ViewSelectorComponent;
import com.netscape.management.client.util.Browser;
import com.netscape.management.client.util.ResourceSet;

/**
 * Setup the topology page with topology information
 */
class TopologyResourcePage extends ResourcePage implements SwingConstants {
    ConsoleInfo _info;
    String _globalParamDN;
    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");
    static String _sTopologyResourcePage = "TopologyResourcePage";
    protected StatusItemSecureMode _statusSecureMode =
            new StatusItemSecureMode(Framework.STATUS_SECURE_MODE);
    protected StatusItemSpacer _statusSpacer = new StatusItemSpacer("SECURE_MODE_SPACER");
    protected ViewSelectorComponent _viewSelectorComponent;
    private boolean canEditCustomViews = true;

    /**
     * constructor
     *
     * @param info global information block
     * @param resourceModel resource model which describe the topology page
     */
    public TopologyResourcePage(ConsoleInfo info, IResourceModel resourceModel, boolean canEditCustomViews) {
        super(resourceModel);
        this.canEditCustomViews = canEditCustomViews;
        setRootVisible(false);
        _info = info;
        _tree.setLargeModel(true);
    }

    /**
      * initialize the page with topology information
      */
    public void initialize(IFramework parent) {
        super.initialize(parent);
        if(canEditCustomViews)
        {
            addMenuItem(Framework.MENU_VIEW,
                    new MenuItemText(
                    _resource.getString(_sTopologyResourcePage,
                    "customview"), "", new CustomViewActionListener()));
        }
        _viewSelectorComponent.initialize(_info);

        expandTreeRow(0);

        boolean secure = _info.get("ldapSecurity").equals("on");
        _statusSecureMode.setSecureMode(secure);
        _statusSecureMode.setToolTipText((secure ?
                                          _resource.getString(_sTopologyResourcePage,"secure") + " ldaps" :
                                          _resource.getString(_sTopologyResourcePage,"unsecure") + " ldap") +
                                         "://" + _info.getHost() + ":" + _info.getPort());
    }


    /**
      * inner class which listens to the custom view information
      */
    class CustomViewActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            _viewSelectorComponent.showConfigDialog();
        }
    }

    public void refresh() {
        _viewSelectorComponent.reloadViewList();
    }

    /**
     * @deprecated not used by Framework
     */
    @Deprecated
    public Object clone() {
        return null;
    }

    /**
      * start the browser with the given URL
      *
      * @param url URL to start up with
      */
    public void startBrowser(String url) {
        Browser b = new Browser();
        b.open(url);
    }

    /**
      * add page specific status items to status bar
      */
    protected void populateStatusItems() {
        _framework.addStatusItem(_statusSpacer, IStatusItem.LEFTFIRST);
        _framework.addStatusItem(_statusSecureMode, IStatusItem.LEFTFIRST);
        super.populateStatusItems();
    }

    /**
      * remove page specific status items to status bar
      */
    protected void unpopulateStatusItems() {
        super.unpopulateStatusItems();
        _framework.removeStatusItem(_statusSecureMode);
        _framework.removeStatusItem(_statusSpacer);
    }

    /**
      * subclassed from ResourcePage, to create CustomView ComboBox
      */
    protected Component createTree(IResourceModel resourceModel) {

        JPanel pnlLeft = new JPanel();
        pnlLeft.setLayout(new GridBagLayout());

        GridBagConstraints gbc;
        gbc = new java.awt.GridBagConstraints ();

        _viewSelectorComponent = new ViewSelectorComponent(resourceModel);

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = java.awt.GridBagConstraints.NORTHWEST;
        pnlLeft.add (_viewSelectorComponent, gbc);

        Component topologyComponent = super.createTree(resourceModel);
        if (topologyComponent instanceof JScrollPane) {
            Component c = ((JScrollPane)topologyComponent).getViewport().getView();
            if (c != null && c instanceof JTree) {
                ((JComponent)c).getAccessibleContext().
                    setAccessibleDescription(_resource.getString(_sTopologyResourcePage,
                                                                 "topologyTree_tt"));
            }
        }

        gbc = new java.awt.GridBagConstraints ();

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 1;
        gbc.weighty = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.anchor = java.awt.GridBagConstraints.NORTHWEST;
        pnlLeft.add (topologyComponent, gbc);

        _viewSelectorComponent.addSelectionActionListener(
                new ViewChangeActionListener());

        return pnlLeft;
    }

    /**
     * Set the new resource model
     */
    void  setView (ResourceModel newModel) {
        if (newModel != null) {
            ResourceObject newRoot =
                    (ResourceObject) newModel.getRoot();
            TopologyModel model = (TopologyModel) getTreeModel();
            model.setRoot(newRoot);
            setRootVisible(newModel.isRootVisible());
            model.refreshTree(TopologyResourcePage.this);
            selectTreeRow(0);
        }
    }

    /**
      * inner class which listens to custom view changes
      */
    class ViewChangeActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            setView((ResourceModel)
               _viewSelectorComponent.getSelectedTreeModel());
        }
    }
}
