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
package com.netscape.management.client.topology.customview;

import java.awt.Component;
import java.awt.event.ActionListener;
import java.util.Enumeration;
import java.util.Vector;

import javax.swing.Box;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.tree.TreeModel;

import com.netscape.management.client.Framework;
import com.netscape.management.client.IResourceObject;
import com.netscape.management.client.ResourceModel;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.preferences.LDAPPreferenceManager;
import com.netscape.management.client.preferences.LDAPPreferences;
import com.netscape.management.client.topology.ICustomView;
import com.netscape.management.client.topology.TopologyInitializer;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.LDAPUtil;
import com.netscape.management.nmclf.SuiConstants;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;
import netscape.ldap.util.DN;

/**
 * view selector in the topology page
 */
public class ViewSelectorComponent extends Box implements SwingConstants, SuiConstants {
    LDAPConnection ldc = null;
    String privateViewDN = null;
    String publicViewDN = null;
    TreeModel defaultViewTreeModel = null;
    boolean isViewReloading = false;
    JComboBox viewComboBox = new JComboBox();
    ConsoleInfo consoleInfo;
    ActionListener selectionListener;
    LDAPPreferences userViewPreferences;  // private view preferences

    static String i18n(String id) {
        return TopologyInitializer._resource.getString("customview", id);
    }
    static String _defaultViewPref = "DefaultView";

    /**
      * constructor
      *
      * @param defaultdefaultViewTreeModel current tree model for the custom view
      */
    public ViewSelectorComponent(TreeModel defaultdefaultViewTreeModel) {
        super(VERTICAL);
        viewComboBox.setToolTipText(i18n("currentViewName_tt"));
        this.defaultViewTreeModel = new ResourceModel(
                (IResourceObject) defaultdefaultViewTreeModel.getRoot());
        add(viewComboBox);
        add(Box.createVerticalStrut(COMPONENT_SPACE));
    }

    /**
      * initialize the custom view selector
      *
      * @param ci console information
      */
    public void initialize(ConsoleInfo ci) {
        consoleInfo = ci;
        ldc = consoleInfo.getLDAPConnection();
        LDAPPreferenceManager pm;
        LDAPPreferences publicViewPreferences;

        pm = new LDAPPreferenceManager(ci.getLDAPConnection(),
                ci.getUserPreferenceDN(), Framework.IDENTIFIER,
                Framework.MAJOR_VERSION);
        userViewPreferences = (LDAPPreferences) pm.getPreferences("CustomViews");  // private views
        privateViewDN = userViewPreferences.getDN();

        pm = new LDAPPreferenceManager(ci.getLDAPConnection(),
                "ou=Global Preferences," + LDAPUtil.getInstalledSoftwareDN(), "admin",
                Framework.MAJOR_VERSION);
        publicViewPreferences = (LDAPPreferences) pm.getPreferences("PublicViews");

        publicViewDN = publicViewPreferences.getDN();

        Vector allViews = reloadViewList();

        /**
         * Set the default view from preferences
         */
        if (Debug.isEnabled()){
            Debug.println("pub defaultView=" +
                publicViewPreferences.getString(_defaultViewPref));
            Debug.println("user defaultView=" +
            userViewPreferences.getString(_defaultViewPref));
        }
        setDefaultView(allViews,
            userViewPreferences.getString(_defaultViewPref),
            publicViewPreferences.getString(_defaultViewPref));
    }

    /**
      * add a selection listener for the custom view selector.
      *
      * @param l selection listener
      */
    public void addSelectionActionListener(ActionListener l) {
        selectionListener = l;
        viewComboBox.addActionListener(l);
    }

    /**
      * get the current selected custom view tree model
      */
    public TreeModel getSelectedTreeModel() {
        if (isViewReloading)
            return null;

        ViewInfo vi = (ViewInfo) viewComboBox.getSelectedItem();

        saveDefaultViewPreference(vi);

        ICustomView customView = vi.getClassInstance();
        if (customView != null) {
            String dn = getViewDN(vi);
            customView.initialize(ldc, dn);
            return customView.getTreeModel();
        }
        return defaultViewTreeModel;
    }

    /**
     * Save the selected view as the default one
     */
    void saveDefaultViewPreference(ViewInfo vi) {
        String viewID = vi.getID();
        String viewRef="";
        if (viewID != null) {
            viewRef = getViewDN(vi);
        }
        String curViewRef = userViewPreferences.getString(_defaultViewPref);
        if (curViewRef != null) {
            DN curViewDN = new DN(curViewRef);

            if (curViewDN.equals(new DN(viewRef))) {
                if (Debug.isEnabled()) {
                    Debug.println(6,"do not need to save DefaultView");
                }
               return ;
            }
            else if (Debug.isEnabled()) {
                Debug.println(5, "save pref DefaultView="+viewRef);
            }
        }

        userViewPreferences.set(_defaultViewPref, viewRef);
        userViewPreferences.save();
    }

    /**
     * Set the default view from preferences, check first user preferences then the public ones
     */
    void setDefaultView(Vector allViews, String userDefaultView, String domainDefaultView) {
        String defaultView = (userDefaultView == null) ? domainDefaultView : userDefaultView;

        if (defaultView != null && defaultView.length() > 0) {

            // Compare DNs using ldap.DN to handles blanks that can be ignored
            DN dnDefaultView = new DN(defaultView);
            DN dnView = null;
            for (int i=0; i < allViews.size(); i++) {
                ViewInfo vi = (ViewInfo) allViews.elementAt(i);

                if (vi.getID() == null) {
                    continue;
                }
                dnView = new DN(getViewDN(vi));
                if (dnView.equals(dnDefaultView)) {
                    if (Debug.isEnabled()) {
                        Debug.println("Select Default View - " + vi);
                    }
                    final ViewInfo fvi = vi;
                    SwingUtilities.invokeLater(new Runnable() {
                       public void run() {
                           viewComboBox.setSelectedItem(fvi);
                       }
                    });
                    break;
                }
            }
        }
    }

    public TreeModel getUserDefaultViewModel() {
        return defaultViewTreeModel;
    }

    private String getViewDN(ViewInfo vi)
    {
        String baseDN;

        if(vi.isPublic())
            baseDN = publicViewDN;
        else
            baseDN = privateViewDN;

        return ("cn=" + vi.getID() + "," + baseDN);
    }

    /**
      * reload all the custom views selection in the list box
      */
    public Vector reloadViewList() {
        isViewReloading = true;
        int index = viewComboBox.getSelectedIndex();
        viewComboBox.removeAllItems();
        viewComboBox.addItem(
                new ViewInfo(null, i18n("DefaultView"), null));

        Vector allViews = new Vector();

        // load topology view plugins
        // misnamed container "CustomView" should be maintained for compatibility
        loadViewsFromDN(allViews, "cn=CustomView," + LDAPUtil.getAdminGlobalParameterEntry(), null, true);

        // Load public user custom views, first load system/app views
        loadViewsFromDN(allViews, publicViewDN,
            "(&(Objectclass=nsCustomView)(nsViewFlags=systemView))", true);
        // then user public views
        loadViewsFromDN(allViews, publicViewDN,
            "(&(Objectclass=nsCustomView)(!(nsViewFlags=systemView)))", true);

        // load private user custom views
        loadViewsFromDN(allViews, privateViewDN, null, false);

        for (Enumeration e = allViews.elements(); e.hasMoreElements();) {
            ViewInfo vi = (ViewInfo) e.nextElement();
            viewComboBox.addItem(vi);
        }
        if ((index != -1) && (index < viewComboBox.getItemCount()))
            viewComboBox.setSelectedIndex(index);
        isViewReloading = false;

        return allViews;
    }

    /**
      * show the custom view configuration dialog
      */
    public void showConfigDialog() {
        Vector userViews = new Vector();

        // load public user custom views
        loadViewsFromDN(userViews, publicViewDN,
            "(&(Objectclass=nsCustomView)(!(nsViewFlags=systemView)))", true);

        // load private user custom views
        loadViewsFromDN(userViews, privateViewDN, null, false);

        ViewSelectorDialog dialog = new ViewSelectorDialog(
                getParentFrame(ViewSelectorComponent.this), userViews,
                defaultViewTreeModel, ldc, privateViewDN, publicViewDN, consoleInfo);
        String viewID = ((ViewInfo) viewComboBox.getSelectedItem()).getID();
        dialog.show();
        reloadViewList();
        int itemToSelect = 0;
        int count = viewComboBox.getItemCount();
        for (int i = 0; i < count; i++) {
            ViewInfo vi = (ViewInfo) viewComboBox.getItemAt(i);
            String currentID = vi.getID();
            if ((currentID != null) && (currentID.equals(viewID))) {
                itemToSelect = i;
                break;
            }
        }
        viewComboBox.setSelectedIndex(itemToSelect);
        selectionListener.actionPerformed(null);
    }

    private void loadViewsFromDN(Vector viewVector, String customViewDN, String filter, boolean isPublic)
    {
        LDAPEntry ldapEntry = null;
        LDAPSearchResults result = null;

        if (filter == null) {
            filter = "(Objectclass=nsCustomView)";
        }

        try {
            result = ldc.search(customViewDN, LDAPv3.SCOPE_ONE, filter, null, false);
            if (result != null) {
                try {
                    while (result.hasMoreElements()) {
                        ldapEntry = result.next();
                        if (ldapEntry != null) {
                            ViewInfo vi = new ViewInfo(ldapEntry);
                            vi.setPublic(isPublic);
                            viewVector.addElement(vi);
                        }
                    }
                } catch (Exception e) {
                    // ldap exception
                }
            }
        }
        catch (LDAPException e) {
            Debug.println(0, "Cannot load custom views, error code= " + e.getLDAPResultCode());
            Debug.println(0, "<dn=" + customViewDN + ">");
        }
    }

    private JFrame getParentFrame(Component c) {
        do {
            c = c.getParent();
        } while (c != null && !(c instanceof JFrame))
            ;

        if (c != null)
            return (JFrame) c;

        return null;
    }
}
