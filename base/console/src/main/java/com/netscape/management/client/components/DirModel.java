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
package com.netscape.management.client.components;
import java.util.*;
import java.io.Serializable;
import javax.swing.tree.TreePath;
import javax.swing.*;
import javax.swing.event.*;
import netscape.ldap.*;
import com.netscape.management.client.util.*;

/**
  * Directory model is a tree model which describes how to
  * display the directory contents.
  *
  * @author  rweltman
  * @version %I%, %G%
  */
  
public class DirModel implements IDirModel,
                                 IDirContentListener,
                                 Serializable {

    /**
     * Default constructor for deserialization
     */
    public DirModel() {
        setChildFilter( initializeChildFilter() );
    }

    /**
     * Constructor of the model that doesn't populate the tree.
     * You must call initialize() to populate it.
     *
     * @param ldc Connection to LDAP server
     */
    public DirModel( LDAPConnection ldc ) {
        this();
        setLDAPConnection( ldc );
    }

    /**
     * Constructor of the model with the root object passed in.
     * Suffix nodes are retrieved and added to the tree.
     *
     * @param root root object
     * @param ldc Connection to LDAP server
     */
    public DirModel( Object root, LDAPConnection ldc ) {
        this( ldc );
        initialize( root );
    }

    /**
     * Set default filter which causes only container nodes to
     * be displayed in the tree
     */
    private String initializeChildFilter() {
        Hashtable containers = getContainers();
        /* Due to a server bug, "numsubordinates>=1" is not
         * indexed, but
         * "(&(numsubordinates=*)(numsubordinates>=1))" is,
         * in Netscape Directory Server 4.0
         */
        String filter =
            "(|(&(numsubordinates=*)(numsubordinates>=1))";
        Enumeration e = containers.keys();
        while( e.hasMoreElements() )
            filter += "(objectclass=" +
                (String)e.nextElement() + ")";
        filter += ")";
        Debug.println( "DirModel.initializeChildFilter: " +
                       filter );
        return filter;
    }

    /**
     * Report if the model will supply node objects for tree
     * nodes. If false (the default), only container nodes will
     * appear.
     *
     * @return <CODE>true</CODE> if leaf nodes are to be
     * displayed in the tree
     */
    public boolean getAllowsLeafNodes() {
        return _allowLeafNodes;
    }

    /**
     * Determines if the model will supply node objects for
     * tree nodes. If false (the default), only container nodes
     * will appear.
     *
     * @param allow <CODE>true</CODE> if leaf nodes are to be
     * displayed in the tree
     */
    public void setAllowsLeafNodes( boolean allow ) {
        if ( allow ) {
            setChildFilter( "objectclass=*" );
        } else {
            setChildFilter( initializeChildFilter() );
        }
        _allowLeafNodes = allow;
        contentChanged();
    }

    /**
     * Used between DirNode and DirModel, to manage the search
     * filter used to find children of a node.
     *
     * @return The search filter to be used to find immediate
     * children
     */
    public String getChildFilter() {
        return _childFilter;
    }

    /**
     * Set the search filter used to find children of a node.
     *
     * @param filter The search filter to be used to find
     * direct children
     */
    public void setChildFilter( String filter ) {
        _childFilter = filter;
    }

    /**
     * Create root node and a node for each suffix
     *
     * @param root Root node for the tree. If null, a new root
     * node will be created and the root DSE will be searched
     * for suffixes
     */
    public void initialize( Object root ) {
        if ( root == null ) {
            root =
                new RootDirNode( this,
                                 getShowsPrivateSuffixes() );
            Debug.println(9, "DirModel.initialize: new root");
        } else {
            ((DirNode)root).setModel( this );
            Debug.println(9, "DirModel.initialize: old root=" +
                          root);
        }
        setRoot( root );
    }

    /**
     *  Get a child node of a node.
     *
     * @param node Parent node
     * @param index Position of the child
     * @return The child of the specified node
     */
    public Object getChild(Object node, int index) {
        IDirNode sn = (IDirNode) node;
        return sn.getChildAt(index);
    }

    /**
     *  return the number of children.
     * 
     * @param node node to be checked
     * @return number of children of the specified node.
     */
    public int getChildCount(Object node) {
        IDirNode sn = (IDirNode) node;
        return sn.getChildCount();
    }

    /**
      * Returns the index of a particular child node.
      * @param parent Parent node
      * @param child Child node
      * @return Position of the child
      */
    public int getIndexOfChild(Object parent, Object child) {
        return ((IDirNode) parent).getIndex(
                (IDirNode) child);
    }

    /**
     * Adds a listener that is interested in receiving
     * TreeModelListener events. Called by JTree.
     *
     * @param l An object interested in receiving
     * TreeModelListener events
     */
    public void addTreeModelListener(TreeModelListener l) {
        _listenerList.add(TreeModelListener.class, l);
    }

    /**
     * Removes a listener that is interested in receiving
     * TreeModelListener events. Called by JTree.
     *
     * @param l An object interested in receiving
     * TreeModelListener events
     */
    public void removeTreeModelListener(TreeModelListener l) {
        _listenerList.remove(TreeModelListener.class, l);
    }

    /**
      * Informs the tree that a particular node has changed
      *
      * @param node The node that changed
      * @see EventListenerList
      */
    public void fireTreeNodeChanged( DirNode node ) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        TreeModelEvent e = null;
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for ( int i = listeners.length - 2; i >= 0; i -= 2 ) {
            if ( listeners[i] == TreeModelListener.class ) {
                // Lazily create the event:
                if (e == null) {
                    e = new TreeModelEvent(
                        this, node.getPath() );
                }
                TreeModelListener l =
                    (TreeModelListener)listeners[i + 1];
                l.treeNodesChanged(e);
            }
        }
    }

    /**
      * Informs tree that a particular node's structure has
      * changed and its view needs to be updated.
      * @param node The node at the root of the changes
      * @see EventListenerList
      */
    public void fireTreeStructureChanged( IDirNode node ) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        TreeModelEvent e = null;
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for ( int i = listeners.length - 2; i >= 0; i -= 2 ) {
            if ( listeners[i] == TreeModelListener.class ) {
                // Lazily create the event:
                if (e == null)
                    e = new TreeModelEvent(
                        this, ((DirNode)node).getPath());
                TreeModelListener l =
                    (TreeModelListener)listeners[i + 1];
                l.treeStructureChanged( e );
            }
        }
    }

    /**
      * Called when user has altered the value for the item
      * identified by path to newValue.
      * Called by JTree
      *
      * @param path Path to the changed node
      * @param newValue New value of the node
      */
    public void valueForPathChanged(TreePath path,
                                    Object newValue) {
    }

    /**
     *  check whether the node is a leaf node or not
     *
     * @param node node to be checked
     * @return true if the node is leaf, false otherwise.
     */
    public boolean isLeaf( Object node ) {
        IDirNode sn = (IDirNode) node;
        return ( sn.isLeaf() );
    }

    /**
     * Called when the tree structure has changed radically;
     * read a new tree from the server.
     */
    public void contentChanged() {
        newTree();
    }

    void repaintObject( IDirNode node ) {
        Debug.println( "DirModel.repaintObject: " +
                       node );
        fireTreeStructureChanged( (DirNode)node );
    }

    private void newTree() {
        DirNode root =
            new RootDirNode( this, "",
                             getShowsPrivateSuffixes() );
        Debug.println(9, "DirModel.newTree: new root");
        setRoot( root );
        refreshTree();
    }

    private void refreshNode( IDirNode node ) {
        node.load();
        repaintObject( node );
    }

    private void refreshTree() {
        refreshNode( (IDirNode)getRoot() );
    }

    /**
     * Returns the server connection used to populate the tree.
     *
     * @return the server connection used to populate the tree
     */
    public LDAPConnection getLDAPConnection() {
        return _ldc;
    }

    /**
     * Sets the server connection used to populate the tree.
     *
     * @param ldc the server connection used to populate the
     * tree
     */
    public void setLDAPConnection( LDAPConnection ldc ) {
        // Use a cloned ldap connection. A workaround for lapjdk bug 530427.
        // See comment for DirNode.NOLIMIT_BACKLOG constant
        if (_ldc != null)
        {
            try {
                _ldc.disconnect(); // a soft disconnect as this is a clone
            }
            catch (Exception e) {}
        }        
        _ldc = (ldc == null) ? null : (LDAPConnection)ldc.clone();
    }

    protected void finalize() {
        // See setLDAPConnection()
        if (_ldc != null)
        {
            try {
                _ldc.disconnect(); // a soft disconnect as this is a clone
                _ldc = null;
            }
            catch (Exception e) {}
        }
        try {
            super.finalize();
        }
        catch (Throwable t) {}
    }
    
    /**
      * Returns root node of the tree.
      *
      * return Root node of the tree
      */
    public Object getRoot() {
        return _root;
    }

    /**
      * Sets root node of the tree.
      *
      * @param root Root node for the tree
      */
    public void setRoot(Object root) {
        _root = (IDirNode) root;
			
    }
    
    /**
     * Get the parameter which determines if the
     * ManagedSAIT control is sent with each search.
     *
     * @returns <CODE>true</CODE> if referrals are to be
     * followed
     */
    public boolean getReferralsEnabled() {
        return _followReferrals;
    }

    /**
     * Set a parameter for future searches, which determines if
     * the ManagedSAIT control is sent with each search. If
     * referrals are disabled, the control is sent and you will
     * receive the referring entry back.
     *
     * @param on <CODE>true</CODE> (the default) if referrals
     * are to be followed
     */
    public void setReferralsEnabled( boolean on ) {
        _followReferrals = on;
    }

    /**
     * Get the schema of the Directory instance
     *
     * @return A reference to a schema object.
     */
    public LDAPSchema getSchema() {
        if ( _schema == null ) {
            _schema = new LDAPSchema();
            try {
                _schema.fetchSchema( getLDAPConnection() );
            } catch ( LDAPException e ) {
                Debug.println( "DirModel.getSchema: " + e );
                _schema = null;
            }
        }
        return _schema;
    }

    /**
     * Sets a reference to the schema of the Directory instance
     *
     * @param schema A reference to a schema object.
     */
    public void setSchema( LDAPSchema schema ) {
        _schema = schema;
    }

    /**
     * Report if the model will show private suffixes.
     * If true (the default), private suffixes will appear.
     *
     * @return <CODE>true</CODE> if private suffixes are to be
     * displayed in the tree
     */
    public boolean getShowsPrivateSuffixes() {
        return _showPrivateSuffixes;
    }

    /**
     * Determines if the model will show private suffixes in
     * addition to public suffixes. If false (the default),
     * only public suffixes will appear.
     *
     * @param allow <CODE>true</CODE> if private suffixes are
     * to be displayed in the tree
     */
    public void setShowsPrivateSuffixes( boolean showPrivate ) {
        _showPrivateSuffixes = showPrivate;
        contentChanged();
    }

    /**
     * Get object classes which are to be considered containers
     * from a properties file.
     *
     */
    private static Hashtable initContainerNames() {
        Hashtable h = new Hashtable();
        String items =
            _resource.getString( _section, "containers" );
        Debug.println( "DirModel.initContainerNames" );
        if ( items != null ) {
            StringTokenizer st =
                new StringTokenizer( items, " " );
            int i = 0;
            while ( st.hasMoreTokens() ) {
                String name = st.nextToken().toLowerCase();
                Debug.println(
                    "  added container type " + name );
                h.put( name, name );
            }
        }
        return h;
    }

    /**
     * Add the name of an object class to be considered a
     * container.
     *
     * @param name Name of an object class to be considered a
     * container.
     */
    public void addContainerName( String name ) {
        _cContainers.put( name, name );
    }

    /**
     * Used between DirNode and DirModel, to manage the list of
     * objectclasses which are to be considered containers.
     *
     * @return A hashtable containing objectclasses to be
     * considered containers
     */
    public Hashtable getContainers() {
        if ( _cContainers == null ) {
            _cContainers = initContainerNames();
        }
        return _cContainers;
    }
    
    /**
     * Find an appropriate image for a node, based on the
     * objectclasses specified and whether or not it is a
     * leaf node.
     *
     * @param objectClasses Hashtable containing objectclasses
     * to look for an icon for
     * @param isLeafNode true if this is for a leaf node
     * @return an appropriate image
     */
    public ImageIcon checkIcon( Hashtable objectClasses,
                                boolean isLeafNode ) {
        String iconName = "";
        Enumeration e = objectClasses.keys();
        while ( e.hasMoreElements() ) {
            String s = ((String)e.nextElement()).toLowerCase();
            iconName = (String)_icons.get( s );
            if ( iconName == null ) {
                iconName = _resource.getString( _section,
                                                s+"-icon" );
                if ( iconName == null )
                    iconName = "";
                _icons.put( s, iconName );
            }
            if ( !iconName.equals( "" ) )
                break;
        }
        if ( iconName.equals( "" ) ) {
            if ( isLeafNode )
                iconName = _defaultImageName;
            else
                iconName = _defaultFolderImageName;
        }
        return new RemoteImage(DirNode.IMAGE_PATH + iconName );
    }
    
    /**
     * Sets an icon image for an object class
     * @param objecClass the name of the object class
     * @param fileName the name of the file containing the image icon
     */
    public void setObjectClassIcon(String objectClass, String fileName){
        _icons.put(objectClass, fileName);
        contentChanged();
    }
     
    /**
     * Initialize default image for leaf nodes if none are
     * defined for the objectclasses it contains
     *
     * @return the name of the default image file
     */
    private static String initDefaultIconName() {
        String defaultImageName =
            _resource.getString( _section,
                                 "default-icon" );
        if ( defaultImageName == null ) {
            defaultImageName = "genobject.gif";
        }
        return defaultImageName;
    }

    /**
     * Initialize default image for container nodes if none are
     * defined for the objectclasses it contains
     *
     * @return the name of the default image file
     */
    private static String initDefaultFolderIconName() {
        String defaultImageName =
            _resource.getString( _section,
                                 "default-folder-icon" );
        if ( defaultImageName == null ) {
            defaultImageName = "folder.gif";
        }
        return defaultImageName;
    }

    // Properties for this component (strings)
    static ResourceSet _resource =new ResourceSet("com.netscape.management.client.components.components");
    // Section of the properties file to use
    private static final String _section = "dirBrowser";

    // Active connection to directory
    private LDAPConnection _ldc;
    // Schema definitions
    private LDAPSchema _schema = null;
    // Control to use if referrals are not to be followed
    private static LDAPControl _manageDSAITControl =
            new LDAPControl( LDAPControl.MANAGEDSAIT, true, null );
    // Root node of the tree
    private IDirNode _root = null;
    private boolean _followReferrals = true;
    private boolean _allowLeafNodes = false;
    // List of possible container object classes
    private Hashtable _cContainers = null;
    // Filter string to search for immediate children
    private String _childFilter;
    // Helper object to manager event listeners
    protected EventListenerList _listenerList =
        new EventListenerList();
    // Set this to false to NOT show private suffixes
    private boolean _showPrivateSuffixes = true;
    // Icons for various object classes
    static private Hashtable _icons = new Hashtable();
    // Default image name for tree nodes
    static private String _defaultImageName =
        initDefaultIconName();
    static private String _defaultFolderImageName =
        initDefaultFolderIconName();
}
