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

import java.awt.Toolkit;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.ImageIcon;
import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.TreeModel;

import com.netscape.management.client.ResourceModel;
import com.netscape.management.client.ResourceObject;
import com.netscape.management.client.console.Console;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.console.VersionInfo;
import com.netscape.management.client.topology.ICustomView;
import com.netscape.management.client.topology.IServerObject;
import com.netscape.management.client.topology.ITopologyPlugin;
import com.netscape.management.client.topology.TopologyInitializer;
import com.netscape.management.client.util.ClassLoaderUtil;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.RemoteImage;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPUrl;
import netscape.ldap.LDAPv3;

/**
 * Custom view
 */
public class CustomView implements ICustomView {
    String _cn;
    String _displayNameRaw = null;
    String _displayIconRaw= null;
    String _descriptionRaw = null;
    String _configuration = null;
    String _className = null;
    String _resourceRef = null;
    boolean _fSystemView = false;
    boolean _fShowTopContainer = false;
    boolean _fHideContainerIfEmpty = false;
    String _customViewDN;
    LDAPConnection _ldc;
    LDAPEntry _ldapEntry;
    CustomView _parentView;
    Vector _childViews;
    ResourceModel _model;
    ConsoleInfo _info;
    ImageIcon _icon;
    String _name;
    String _description;

    private static RemoteImage _defaultIcon = new RemoteImage(
                                                              TopologyInitializer._resource.getString("image", "folder"));

    /**
     * constructor
     */
    public CustomView() {
    }

    /**
     * constructor
     * @param ldapEntry an ldapEntry that corresponds to this view
     */
    public CustomView(LDAPEntry ldapEntry) {
        if (ldapEntry == null) {
            Debug.println(0, "CustomView(LDAPEntry ldapEntry) ldapEntry is null");
            return;
        }
        _ldapEntry = ldapEntry;
        _customViewDN = _ldapEntry.getDN();
        _info = Console.getConsoleInfo();

        _displayNameRaw = getFirstAttributeValue(_ldapEntry, "nsDisplayName");
        // Default name is nsDisplayName is not specified
        _cn = getFirstAttributeValue(_ldapEntry, "cn");
        _displayIconRaw = getFirstAttributeValue(_ldapEntry, "nsDisplayIcon");
        _configuration  = getFirstAttributeValue(_ldapEntry, "nsViewConfiguration");
        _className      = getFirstAttributeValue(_ldapEntry, "nsClassName");
        _resourceRef    = getFirstAttributeValue(_ldapEntry, "seeAlso");
        _descriptionRaw = getFirstAttributeValue(_ldapEntry, "description");
        getViewFlags(_ldapEntry, "nsViewFlags");

    }

    /**
     * initialize the custom view
     *
     * @param ldc LDAPConnection
     * @param customViewDN custom view DN
     */
    public void initialize(LDAPConnection ldc, String customViewDN) {
        _ldc = ldc;
        _customViewDN = customViewDN;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer("CustomView:{");
        sb.append(" <displayName>=").append(_displayNameRaw);
        sb.append(" <displayIcon>=").append(_displayIconRaw);
        sb.append(" <configuration>=").append(_configuration);
        sb.append(" <className>=").append(_className);
        sb.append(" <resourceRef>=").append(_resourceRef);
        sb.append(" <description>=").append(_descriptionRaw);
        sb.append(" <flags>=");
        if (_fSystemView) {
            sb.append("systemView ");
        }

        if (_fShowTopContainer) {
            sb.append("showTopContainer ");
        }

        if (_fHideContainerIfEmpty) {
            sb.append("hideContainerIfEmpty ");
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * return the first attribute value
     *
     * @param ldapEntry ldap entry
     * @param name name of the attribute to be retrieve
     * @return return the first element of the attribute
     */
    public static String getFirstAttributeValue(LDAPEntry ldapEntry,
                                                String name) {
        LDAPAttribute attr = ldapEntry.getAttribute(name);
        if (attr != null) {
            Enumeration attr_enum = attr.getStringValues();
            if (attr_enum != null)
                try {
                    return (String) attr_enum.nextElement();
                } catch (Exception e)// if value stored was null, enum fails
                    {
                        Debug.println(0, "CustomView: no configuration data");
                    }
        }
        return null;
    }

    /**
     * Reads view flags from the attribute nsViewFlags
     *
     * @param ldapEntry ldap entry
     * @param name name of the attribute to be retrieve
     */
    void getViewFlags(LDAPEntry ldapEntry,
                      String name) {
        LDAPAttribute attr = ldapEntry.getAttribute(name);
        if (attr == null) {
            return;
        }

        Enumeration attr_enum = attr.getStringValues();
        while (attr_enum != null && attr_enum.hasMoreElements()) {
            String flag = ((String)attr_enum.nextElement()).trim();
            if (flag.equalsIgnoreCase("showTopContainer")) {
                _fShowTopContainer = true;
            }
            else if (flag.equalsIgnoreCase("hideContainerIfEmpty")) {
                _fHideContainerIfEmpty = true;
            }
            else if (flag.equalsIgnoreCase("systemView")) {
                _fSystemView = true;
            }
            else {
                Debug.println(1,"CustomView.getViewFlags() unknown flag <" + flag + ">");
            }
        }
    }

    /**
     * Get the display name of the custom view (displayName attribute)
     *
     * @return display name of the custom view
     */
    public String getDisplayName() {
        if (_name != null) {
            return _name;
        }
        if (_displayNameRaw != null) {
            return (_name = getStringAsProperty(_displayNameRaw));
        }
        return _name;
    }

    /**
     * Get the id of the custom view (cn attribute)
     *
     * @return display name of the custom view
     */
    public String getID() {
        return _cn;
    }

    /**
     * Get the description of the custom view
     *
     * @return description of the custom view
     */
    public String getDescription() {
        if (_description != null) {
            return _description;
        }
        return (_description = getStringAsProperty(_descriptionRaw));
    }

    /**
     * Check if the view is a non-user view
     *
     * @return true if system view, false is user view
     */
    public boolean isSystemView() {
        return _fSystemView;
    }

    /**
     * Get the string from a reference to a property file
     *
     * Check if the propRef is a reference to a property in a file.
     * The format is token@propertyFilePath@jar[@Location].
     *
     * @param propRef  A reference to a property token
     * @return Resolved string for the property or original propRef string if
     * no valid property is found
     */
    String getStringAsProperty(String propRef) {

        if (propRef == null) {
            return propRef;
        }

        int atIdx = propRef.indexOf("@");
        if (atIdx > 0) {
            String propName = propRef.substring(0, atIdx);
            String propFile = propRef.substring(atIdx + 1);
            Properties props = new Properties();
            java.io.InputStream is = null;
            try {
                is = ClassLoaderUtil.getResourceAsStream(_info, propFile, null);
                if (is != null) {
                    props.load(is);
                    String prop = props.getProperty(propName);
                    if (prop != null) {
                        return prop;
                    }
                }
            }
            catch (Exception e) {
                Debug.println(0, "Can not load " + propFile);
            }
        }
        return propRef;
    }

    /**
     * Get the display icon of the custom view
     *
     * @return display icon of the custom view
     */
    public ImageIcon getDisplayIcon() {
        if (_icon != null) {
            return _icon;
        }

        // Get the icon from the class loader. The icon is specified in
        // format iconPath[@jar[@Location]]
        if (_displayIconRaw != null) {
            byte[] buf = ClassLoaderUtil.getResource(_info, _displayIconRaw);
            if (buf != null) {
                _icon = new ImageIcon(Toolkit.getDefaultToolkit().createImage(buf));
            }
            else {
                _icon = _defaultIcon;
            }
        }
        // Override resourceRef icon, only if the icon is explicitly set
        else if (_resourceRef == null) {
            _icon = _defaultIcon;
        }

        return _icon;
    }

    /**
     * Get the referenced resource
     *
     * @return the referenced resource
     */
    public ResourceObject getResourceRef() {
        return getTopologyResource(_resourceRef);
    }


    /**
     * Get the parent view for this view
     *
     * @return the parent view
     */
    public CustomView getParentView() {
        return _parentView;
    }

    /**
     * set the parent view for this view
     *
     * @param parent the parent view
     */
    public void  setParentView(CustomView parent) {
        _parentView = parent;
    }

    /**
     * Load all instances of nsTopologyCustomView which are immediate
     * children of this view entry
     */
    private void loadChildViews()
    {
        _childViews = new Vector();
        if(_ldapEntry == null)
            return;

        LDAPEntry childEntry = null;
        CustomView childView = null;
        LDAPSearchResults result = null;

        try {
            result = _ldc.search(_ldapEntry.getDN(), LDAPv3.SCOPE_ONE,
                                 "(objectclass=nsTopologyCustomView)", null, false);
            if (result != null) {
                while (result.hasMoreElements()) {
                    childEntry = result.next();
                    childView = new CustomView(childEntry);
                    childView.setParentView(this);
                    childView.initialize(_ldc, childEntry.getDN());
                    _childViews.addElement(childView);
                }
            }
        }
        catch (LDAPException e) {
            Debug.println(0, "Cannot load custom views, error code= " +
                          e.getLDAPResultCode() + " <dn=" + _ldapEntry.getDN() + ">");
        }
    }

    /**
     * Find a child view by it's ldap entry DN
     */
    static CustomView getChildView(Vector views, String dn) {
        for (int i=0; i < views.size(); i++) {
            CustomView view = (CustomView) views.elementAt(i);
            String viewDN = view._ldapEntry.getDN();
            if (viewDN.equalsIgnoreCase(dn)) {
                return view;
            }
        }
        return null;
    }

    /**
     * parsing the configuration parameter for this custom view
     *
     * @param configuration configuration string
     * @param top the top node of the custom view.
     * @return a list of resource object for the custom view
     */
    public ResourceObject parseConfiguration(String configuration,
                                             ResourceObject top) {
        if (configuration != null) {
            StringTokenizer st = new StringTokenizer(configuration, "|");
            while (st.hasMoreTokens()) {
                String nodeID = st.nextToken();
                Hashtable table =
                    TopologyInitializer.getNetworkTopologyPlugin()
                    ; // hashtable of ITopologyPlugin
                ResourceObject resourceObj = null;
                for (Enumeration e = table.elements();
                     e.hasMoreElements() && resourceObj == null ;) {
                    ITopologyPlugin plugin =
                        (ITopologyPlugin) e.nextElement();
                    resourceObj = plugin.getResourceObjectByID(nodeID);
                }

                if (resourceObj != null) {
                    top.add(resourceObj);
                } else {
                    // TODO: try other plugins
                }
            }
        }
        return top;
    }

    void createTreeModel(ResourceObject parent) {
        Vector childViews = (Vector)_childViews.clone();
        if (_configuration != null && _configuration.length() > 0) {
            String delim = "|";
            // The default delimiter '|' can be ovirriden by specifing
            // a new one as the first character in the nsViewConfiguration.
            // This is required if '|' is used in ldap filters.
            if (! Character.isLetterOrDigit(_configuration.charAt(0))) {
                delim = String.valueOf(_configuration.charAt(0));
            }
            StringTokenizer st = new StringTokenizer(_configuration, delim);

            while (st.hasMoreTokens()) {

                String member = st.nextToken().trim();

                if (member.length() == 0) {
                    continue;
                }
                else if (member.startsWith("ldap://")) { // LDAPUrl memeber
                    try {
                        LDAPUrl url = new LDAPUrl(member);
                        addDynamicNodes(parent, url);
                    }
                    catch (Exception e) {}
                }
                else { // DN member
                    String dn = member;

                    // Child view can be also specified in the memeber list
                    // in order to have a guaranted order or subviews
                    CustomView childView = getChildView(childViews, dn);
                    if (childView != null) {
                        childViews.removeElement(childView);
                        addChildViewNodes(parent, childView);
                    }

                    // A DN pointing to a resource object
                    else {
                        ResourceObject resourceObj = getTopologyResource(dn);
                        if (resourceObj != null) {
                            parent.add(resourceObj);
                        }
                    }
                }
            }
        }

        // Process child views not listed in the member list
        for (int i=0; i < childViews.size(); i++) {
            addChildViewNodes(parent, (CustomView) childViews.elementAt(i));
        }
    }

    /**
     * Link child view model into this view model
     */
    void addChildViewNodes(ResourceObject parent, CustomView childView) {
        TreeModel childModel = childView.getTreeModel();
        if (childModel != null) {
            if (! childView._fHideContainerIfEmpty || childModel.getChildCount(childModel.getRoot()) >0) {
                parent.add((MutableTreeNode)childModel.getRoot());
            }
        }
    }

    /**
     * Add dynamic nodes defined with an ldap filter
     */
    void addDynamicNodes(ResourceObject parent, LDAPUrl url) {
        LDAPSearchResults result = null;
        try {
            result = _ldc.search(url.getDN().trim(), url.getScope(),
                          url.getFilter().trim(),
                          new String[] {VersionInfo.getVersionNumber()}, false);
            while (result != null && result.hasMoreElements()) {
                LDAPEntry rscEntry = result.next();
                ResourceObject rscObj = getTopologyResource(rscEntry.getDN());
                if (rscObj != null) {
                    parent.add(rscObj);
                }
                else {
                    Debug.println(0, "CustomView.addDynamicNodes(), Topology resouce not found " +
                                  rscEntry.getDN());
                }
            }
        }
        catch (LDAPException e) {
            Debug.println(0, "CustomView.addDynamicNodes() Cannot create dynamic view for , <url="
                          + url + "> " + e);
        }
    }

    /**
     * Create root node for this view
     */
    ResourceObject createRootNode() {

        // If className is refencing this class, ignore it. Earlier versions
        // of Console store CustomeView as the nsClassName attribute
        if (_className != null) {
            if (_className.endsWith("customview.CustomView")) {
                _className = null;
            }
        }
        // Otherwise, it must reference a ResourceObject
        if (_className != null) {
            Class c = ClassLoaderUtil.getClass(_info, _className);
            if (c != null) {
                try {
                    ResourceObject obj =(ResourceObject) c.newInstance();
                    // ResourceObject does not have initialize() method,
                    // but IServerObject does
                    if (obj instanceof IServerObject) {
                        ((IServerObject)obj).initialize(_info);
                    }
                    return obj;
                }
                catch (Exception e) {
                    Debug.println(0, "Failed to instantiate ResourceObject from " +
                                  _className + " " + e);
                }
            }
            return null;
        }

        // Return the default view
        return new ViewObject(this);
    }

    /**
     * Lookup a resource object by it's DN in the topology plugin
     */
    ResourceObject getTopologyResource(String dn) {

        if (dn == null) {
            return null;
        }
        Hashtable table = TopologyInitializer.getNetworkTopologyPlugin();

        ResourceObject resourceObj = null;
        Enumeration e = table.elements();
        while(e.hasMoreElements() && resourceObj == null) {
            ITopologyPlugin plugin =(ITopologyPlugin) e.nextElement();
            resourceObj = plugin.getResourceObjectByID(dn);
        }
        return resourceObj;
    }

    /**
     * return the tree model of the custom view
     *
     * @return return the tree model of the custom view
     */
    public TreeModel getTreeModel() {
        if (_model != null) {
            return _model;
        }
        if (_childViews == null) {
            loadChildViews();
        }

        //ResourceObject rootNode = new ResourceObject(_displayNameRaw,
        //        new RemoteImage(
        //        TopologyInitializer._resource.getString("image", "folder")),
        //        new RemoteImage(
        //        TopologyInitializer._resource.getString("image", "largefolder")));

        //_model = new ResourceModel(
        //        parseConfiguration(_configuration, rootNode));

        ResourceObject rootNode = createRootNode();
        createTreeModel(rootNode);
        _model = new ResourceModel(rootNode);
        _model.setRootVisible(_fShowTopContainer);
        return _model;
    }

    /**
     * set the tree model of the custom view
     *
     * @param newTreeModel tree model to be set
     */
    public void setTreeModel(TreeModel newTreeModel) {
        _model = (ResourceModel)newTreeModel;
        _configuration = new String();
        ResourceObject top = (ResourceObject) newTreeModel.getRoot();
        int count = newTreeModel.getChildCount(top);
        Debug.println(7, "CustomView.setTreeModel: count=" + count);
        for (int index = 0; index < count; index++) {
            ResourceObject child =
                (ResourceObject) newTreeModel.getChild(top, index);
            Hashtable table =
                TopologyInitializer.getNetworkTopologyPlugin(); // hashtable of ITopologyPlugin
            String childConfig = null;
            for (Enumeration e = table.elements();
                 e.hasMoreElements() && childConfig == null ;) {
                ITopologyPlugin plugin = (ITopologyPlugin) e.nextElement();
                childConfig = plugin.getIDByResourceObject(child);
            }
            if (childConfig != null) {
                _configuration = _configuration.concat(childConfig + "|");
            }
        }

        if (_configuration != null) {
            try {
                LDAPAttribute attr =
                    new LDAPAttribute("nsViewConfiguration",
                                      _configuration);
                LDAPModification modification =
                    new LDAPModification(LDAPModification.REPLACE,
                                         attr);
                _ldc.modify(_customViewDN, modification);
                Debug.println("CustomView.setTreeModel: " + _configuration + " modification complete");
            } catch (LDAPException e) {
                Debug.println(0, "Cannot save custom view.");
                Debug.println(0, "<dn=" + _customViewDN +
                              " Error code: " + e.getLDAPResultCode() + ">");
            }
        } else {
            Debug.println(0, "CustomView.setTreeModel:  null configuration");
        }
    }
}
