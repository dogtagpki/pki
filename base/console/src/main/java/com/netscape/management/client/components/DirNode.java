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
import java.io.Serializable;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;

import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.RemoteImage;
import com.netscape.management.client.util.ResourceSet;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPControl;
import netscape.ldap.LDAPDN;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPReferralException;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPSortKey;
import netscape.ldap.LDAPUrl;
import netscape.ldap.LDAPv3;
import netscape.ldap.controls.LDAPSortControl;

/**
 * DirNode is the node of each entry in a Directory tree.
 *
 * @author  rweltman
 * @version %I%, %G%
 */
public class DirNode extends DefaultMutableTreeNode
                     implements IDirNode,
                                Serializable {


    /**
     * (526635) Constant used to set a large enough backlog in LDAPConnection
     * (ldc), to override the default one of 100 search results. ldc will
     * block if backlog limit is reached and results are not read. Because of
     * nested search calls in DirNode (make another search while processing
     * search results) the class depends on the backlog setting.
     * Due to bugs is ldapjdk 530426 the backlog needs to be set for each time
     * ldc.getSearchContraints() is called. Also, because of ldapjdk bug
     * 530427 need to clone the connection (see DirModel.setLdapConnection())
     * in order to cleanup cached objects.
     *
     * TODO: This is ,however, just a workaround. The real fix would be to make
     * DirNode use VLV Lists.
     */
    private static final int NOLIMIT_BACKLOG = 999999;


    /**
     * Default constructor
     */
    public DirNode() {
    }

    /**
     * Constructs a bogus entry object in order to display some
     * information about why the object is bogus e.g. it's a
     * bad referral, the user does not have permission to see
     * it, etc.
     *
     * @param isBogus true if this object does not represent a
     * real entry
     */
    protected DirNode( boolean isBogus ) {
        _isBogus = isBogus;
    }

    /**
     * Constructor of the entry object. It will not load the
     * directory information until later. This function will
     * just initialize the internal variables.
     *
     * @param model Directory Tree model.
     * @param dn DN of the Directory entry
     * @param displayName Name to use for rendering this node
     */
    public DirNode( IDirModel model,
                    String dn,
                    String displayName ) {
        initialize( model, dn, displayName );
        Debug.println(9, "DirNode.DirNode(3): dn=" + dn);
    }

    /**
     * Constructor of the entry object. It will not load the
     * directory information until later. This function will
     * just initialize the internal variables.
     *
     * @param model Directory Tree model.
     * @param dn DN of the Directory entry
     */
    public DirNode( IDirModel model,
                    String dn ) {
        /* Figure out a good display name for this node */
        Debug.println(9, "DirNode.DirNode(2): dn=" + dn);
        String displayName = "";
        String[] rdns = LDAPDN.explodeDN( dn, true );
        if ( (rdns != null) && (rdns[0] != null) ) {
            displayName = rdns[0];
        } else {
            displayName = dn;
            Debug.println( "DirNode: cannot explode " +
                           _sDisplayName );
        }
        initialize( model, dn, displayName );
    }

    /**
     * Constructor of the entry object. It will not load the
     * directory information until later. This function will
     * just initialize the internal variables.
     *
     * @param dn DN of the Directory entry
     */
    public DirNode( String dn ) {
        this( null, dn );
        Debug.println(9, "DirNode.DirNode(1): dn=" + dn);
    }

    /**
     * Constructor of the entry object.
     *
     * @param model Directory Tree model.
     * @param entry LDAP entry.
     */
    public DirNode( IDirModel model,
                    LDAPEntry entry ) {
        this( model, entry.getDN() );
        Debug.println(9, "DirNode.DirNode(2a): dn=" +
                      entry.getDN());
        _entry = entry;
        initializeFromEntry( _entry );
    }

    /**
     * Initialize the entry object with a name and icon.
     *
     * @param model Directory Tree model.
     * @param dn DN of the Directory entry
     * @param displayName Name to use for rendering this node
     */
    protected void initialize( IDirModel model,
                               String dn,
                               String displayName ) {
        // initialize all the variables
        _dn = dn;
        _model = model;
        setAllowsChildren(true);
        setName( displayName );
        setIcon(
            new RemoteImage( DirNode.IMAGE_PATH + _defaultImageName ) );
        Debug.println( 9, "DirNode.initialize: " +
                       "(<" + _dn + ">, " +
                       displayName + ")" );
    }

    /**
     * Report the model of this node
     *
     * @return the model of this node
     */
    public IDirModel getModel() {
        return _model;
    }

    /**
     * Set the model of this node
     *
     * @param model the new model of this node
     */
    public void setModel( IDirModel model ) {
        _model = model;
    }

    /**
     * Returns name that is displayed in tree view.
     *
     * @return name that is displayed in tree view.
     */
    public String getName() {
        return _sDisplayName;
    }

    /**
     * Sets name for this node.
     *
     * @param name name for this node.
     */
    public void setName(String name) {
        _sDisplayName = name;
    }

    /**
     * Returns 16x16 image that is displayed by this tree node.
     *
     * @return image that is displayed by this tree node
     */
    public Icon getIcon() {
        return _icon;
    }

    /**
     * Sets 16x16 image that is displayed by this tree node.
     *
     * @param icon image that is displayed by this tree node
     */
    public void setIcon(Icon icon) {
        _icon = icon;
    }

    protected boolean getAllowLeafNodes() {
        return getModel().getAllowsLeafNodes();
    }

    /**
     * Report the entry associated with this node. If the entry
     * has not been retrieved from the Directory yet, it is
     * done now.
     *
     * @return the entry associated with this node. Only a few
     * attributes are retrieved in the entry.
     */
    public LDAPEntry getEntry() {
        Debug.println(9, "DirNode.getEntry: " + getDN() );
        if ( _entry == null ) {
            try {
                /* Fetch the base attributes of the entry */
                _entry = readEntry( getDN(), _baseAttrs );
                initializeFromEntry( _entry );
            } catch ( Exception ex ) {
                Debug.println( "DirNode.getEntry <" +
                               getDN() + "> " + ex );
            }
        }
        return _entry;
    }

    /**
     * Set the entry for this node
     *
     * @param entry the new entry. May be null to force
     * reinitialization.
     */
    public void setEntry( LDAPEntry entry ) {
        _entry = entry;
    }

    /**
     * Initialize default image for leaf nodes if none are
     * defined for the objectclasses it contains
     *
     * @return the name of the default image file
     */
    private static String initDefaultIconName() {
        String defaultImageName =
            _resource.getString( _section, "default-icon" );
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

    /**
     * Get the DN of the entry corresponding to this node
     *
     * @return the DN of the node
     */
    public String getDN() {
        return _dn;
    }

    /**
     * Set the DN of the node
     *
     * @param dn the new DN of the node
     */
    public void setDN( String dn ) {
        _dn = dn;
    }

    protected LDAPConnection getLDAPConnection() {
        if(_model != null)
            return _model.getLDAPConnection();
        return null;
    }

    /**
     * Check if there are children to this node, by
     * initializing from the Directory
     */
    public void load() {
        String dn = getDN();
        Debug.println(9, "DirNode.load <" + dn + ">" );
        removeAllChildren();
        LDAPConnection ldc = getLDAPConnection();
        if ( ldc == null ) {
            Debug.println( "DirNode.load: " +
                           "no LDAP connection" );
            return;
        }
        LDAPEntry entry = readEntry( dn, _baseAttrs );
        if ( entry != null) {
            initializeFromEntry( entry );
        }
        _fLoaded = true;
    }

    /**
     * Read an entry with the specified attributes from the
     * specified DN in the Directory
     *
     * @param dn The DN of the entry to read
     * @param attrs What attributes to read
     * @return an entry, or null
     */
    protected LDAPEntry readEntry( String dn, String[] attrs ) {
        Debug.println(9, "DirNode.readEntry: " + dn );
        try {
            LDAPConnection ldc = getLDAPConnection();
            if ( ldc == null ) {
                Debug.println( "DirNode.readEntry: " +
                               "no LDAP connection" );
                return null;
            }
            LDAPSearchConstraints cons =
                ldc.getSearchConstraints();
            cons.setMaxBacklog(NOLIMIT_BACKLOG);
            if ( !getModel().getReferralsEnabled() ) {
                Debug.println(9, "DirNode.readEntry: " +
                              "no referrals" );
                cons.setServerControls( _manageDSAITControl );
            } else {
                Debug.println(9, "DirNode.readEntry: " +
                              "referrals on" );
            }
            LDAPEntry entry = ldc.read( dn, attrs, cons );
            if ( entry == null ) {
                Debug.println( "DirNode.readEntry: unable " +
                               "to read <" + dn + ">" );
            } else {
                Debug.println(9, "DirNode.readEntry of " + dn +
                              " returned " + entry );
            }
            return entry;
        } catch ( LDAPReferralException e ) {
            Debug.println( "DirNode.readEntry referral " +
                           "problem " + dn + ": " + e );
            LDAPUrl[] urlList = e.getURLs();
            for (int ii = 0; ii < urlList.length; ++ii) {
                Debug.println("DirNode.readEntry: url=" +
                              urlList[ii]);
            }
        } catch ( LDAPException e ) {
            Debug.println( "DirNode.readEntry of " + dn +
                           ": " + e );
        }
        return null;
    }

    /**
     * Report if this node is considered a container. This is
     * true if it is one of a defined list of objectclasses, or
     * if it has children.
     *
     * @return true if the node is considered a container.
     */
    public boolean isContainer() {
        return _fContainer;
    }

    /**
     *  Create all the one level depth child nodes
     */
    public void reload() {
        Debug.println(9, "DirNode.reload: <" + getDN() + ">" );

        /* Get the child list for internal use */
        getChildList();
    }

    /**
     * Create a vector of all the one level depth sub nodes.
     * The nodes are also added as subnodes to this node.
     *
     * @return a Vector of all direct child nodes
     */
    protected Vector getChildList() {
        String dn = getDN();
        Debug.println(9, "DirNode.getChildList: <" + dn +
                      ">, " + getChildFilter() );
        Vector v = null;
        removeAllChildren();

        try {
            LDAPConnection ldc = getLDAPConnection();
            if ( ldc == null ) {
                Debug.println( "DirNode.getChildList: " +
                               "no LDAP connection" );
                return new Vector();
            }
            LDAPSearchConstraints cons =
                ldc.getSearchConstraints();
            // Unlimited search results
            cons.setMaxResults( 0 );
            cons.setMaxBacklog(NOLIMIT_BACKLOG);
            LDAPControl[] controls;
            if ( !getModel().getReferralsEnabled() ) {
                // If not following referrals, send the
                // manageDSAIT control which tells the server
                // to return referral entries as ordinary
                // entries
                controls = new LDAPControl[2];
                controls[0] = _manageDSAITControl;
            } else {
                controls = new LDAPControl[1];
            }
            // Ask the server to sort the results, by
            // specifying a sort control
            String[] sortOrder =
                { "sn", "givenname", "cn", "ou", "o" };
            LDAPSortKey[] keys =
                new LDAPSortKey[sortOrder.length];
            for( int i = 0; i < sortOrder.length; i++ ) {
                keys[i] = new LDAPSortKey( sortOrder[i] );
            }
            controls[controls.length-1] =
                new LDAPSortControl( keys, false );
            cons.setServerControls( controls );
            // Search for immediate children
            LDAPSearchResults result =
                ldc.search( dn, LDAPv3.SCOPE_ONE,
                            getChildFilter(),
                            _baseAttrs, false, cons );
            Debug.println(9, "DirNode.getChildList: <" + dn +
                          "> searching" );

            int found = 0;
            while ( result.hasMoreElements() ) {
                try {
                    // Add each entry found to the tree
                    LDAPEntry entry = result.next();
                    Debug.println(7, "DirNode.getChildList: " +
                                  "adding <" +
                                  entry.getDN() + ">" );
                    DirNode node =
                        new DirNode( getModel(), entry );
                    insert( node, super.getChildCount() );
                    found++;
                } catch (LDAPException e) {
                    Debug.println( "DirNode.getChildList: " +
                                   "<" + dn + ">: " + e );
                }
                if ( (found % 100) == 0 ) {
                    Debug.println(5, "DirNode.getChildList: " +
                                  "added " + found );
                }
            }
            _iChildren = super.getChildCount();
            Debug.println(9, "DirNode.getChildList: <" +
                          dn + "> found " + found);
        } catch (LDAPException e) {
            Debug.println( "DirNode.getChildList: " +
                           "<" + dn + "> " + e );
        }
        return children;
    }

    /**
     *  Count the number of children of this node
     *
     * @param all <CODE>true</CODE> to return all immediate,
     * children, not just containers
     * @return The number of immediate children
     */
    protected int countChildren( boolean all ) {
        String dn = getDN();
        int count = 0;
        try {
            LDAPConnection ldc = getLDAPConnection();
            if ( ldc == null ) {
                Debug.println(
                    "DirNode.countChildren: " +
                    "no LDAP connection" );
                return count;
            }
            LDAPSearchConstraints cons =
                ldc.getSearchConstraints();
            cons.setMaxResults( 0 );
            cons.setMaxBacklog(NOLIMIT_BACKLOG);
            if ( !getModel().getReferralsEnabled() ) {
                cons.setServerControls( _manageDSAITControl );
            }
            String[] attrs = { "dn" }; // Pseudo-attribute
            String filter = (all) ? _allFilter :
                getChildFilter();
            Debug.println(9, "DirNode.countChildren: " +
                          "<" + dn + "> , " + filter );
            LDAPSearchResults result =
                ldc.search( dn, LDAPv3.SCOPE_ONE,
                            filter,
                            attrs, false, cons );

            while ( result.hasMoreElements() ) {
                try {
                    LDAPEntry entry = result.next();
                    Debug.println(9,"DirNode.countChildren: " +
                                  "<" + entry.getDN() + ">" );
                    count++;
                } catch (LDAPException e) {
                    // This is for inline exceptions and
                    // referrals
                    Debug.println( "DirNode.countChildren: " +
                                   "<" + dn + ">  " + e );
                }
            }
        } catch (LDAPException e) {
            // This is for exceptions on the search request
            Debug.println( "DirNode.countChildren: " +
                           "<" + dn + ">: " + e );
        }
        return count;
    }

    /**
     * check whether the node is loaded or not
     *
     * @return true if  the node is loaded, false otherwise.
     */
    public boolean isLoaded() {
        return _fLoaded;
    }

    /**
     * Return the value of the numsubordinates attribute in an
     * entry, or -1 if the attribute is not present
     *
     * @param entry The entry containing the attribute
     * @return -1
     * @deprecated use countChildren instead
     */
    @Deprecated
    static int getCountFromEntry( LDAPEntry entry ) {
        int count = -1;

        // This method was deprecated in response to
        // bugsplat #398002.  Don't include in child
        // counts any children for which we don't have
        // access

        // String s = getFirstValue( entry, SUBORDINATE_ATTR );
        // if ( s != null ) {
        //     count = Integer.parseInt( s );
        //     Debug.println( 9, "DirNode.getCountFromEntry: <" +
        //                    entry.getDN() + "> = " +
        //                    count );
        // } else {
        //     Debug.println( 9, "DirNode.getCountFromEntry: <" +
        //                    entry.getDN() + "> no " +
        //                    SUBORDINATE_ATTR );
        // }
        return count;
    }

    /**
     * Return the value of the numsubordinates attribute in the
     * entry of this node, or -1 if the attribute is not present
     *
     * @return the number of children, or -1
     */
    protected int getCountFromEntry() {
        return getCountFromEntry( getEntry() );
    }

    /**
     * Initialize the node from data in an entry
     *
     * @param entry An entry initialized with data
     */
    public void initializeFromEntry( LDAPEntry entry ) {
        _fLoaded = true;
        _objectClasses = checkObjectClasses( entry );
        _fContainer = checkIfContainer();
        setIcon( ((DirModel)_model).checkIcon( _objectClasses, !isContainer() ) );
        _sCn = checkCn( entry );
        if ( _sCn != null ) {
            setName( _sCn );
        }
    }

    protected boolean hasChildren() {
        return ( _iChildren > 0 );
    }

    protected boolean hasCheckedForChildren() {
        return ( _iChildren >= 0 );
    }

    /**
     * Create hashtable of objectclasses from the entry
     *
     * @param entry Entry containing at least objectclasses
     * @return a hashtable of the objectclasses
     */
    protected Hashtable checkObjectClasses( LDAPEntry entry ) {
        if ( _objectClasses != null )
            return _objectClasses;
        Hashtable objectClasses = new Hashtable();
        LDAPAttribute attr = entry.getAttribute(
            "objectclass" );
        String[] names = { "top" };;
        /* attr should never be null, but there is a bug in
           "cn=monitor,cn=ldbm" */
        if ( attr != null ) {
            Enumeration e = attr.getStringValues();
            while ( e.hasMoreElements() ) {
                String name = (String)e.nextElement();
                objectClasses.put( name.toLowerCase(), name );
            }
        }
        return objectClasses;
    }

    /**
     * Report if this node is to be considered a container
     *
     * @return true if the node has children or is of container
     * type
     */
    protected boolean checkIfContainer() {
        int count = getCountFromEntry();
        if ( count > 0 ) {
            return true;
        }
        if ( count < 0 ) {
            // The numsubordinates attribute was not present.
            // That could be because the server doesn't support
            // it or because we do not have access rights to
            // it.
            count = countChildren( true );
            if ( count > 0 ) {
                return true;
            }
        }
        Hashtable containers = getModel().getContainers();
        Enumeration e = _objectClasses.elements();
        while ( e.hasMoreElements() ) {
            String s = (String)e.nextElement();
            if ( containers.get( s ) != null ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Utility method to get the first String value of an
     * attribute from an entry
     *
     * @param entry An entry
     * @param attrName Name of the attribute
     * @return The first value, or null if not found
     */
    protected static String getFirstValue( LDAPEntry entry,
                                           String attrName ) {
        if(entry != null) {
            LDAPAttribute attr = entry.getAttribute( attrName );
            if ( attr != null ) {
                Enumeration e = attr.getStringValues();
                if ( e.hasMoreElements() ) {
                    return (String)e.nextElement();
                }
            }
        }
        return null;
    }

    /**
     * Find displayName or cn to use as label for this node
     *
     * @param entry Entry containing display attributes
     * @return a label to use
     */
    protected String checkCn( LDAPEntry entry ) {
        String sCn = getFirstValue( entry, "displayName" );
        if ( sCn == null ) {
            sCn = getFirstValue( entry, "cn" );
        }
        return sCn;
    }

    /**
     * Return a specific child of this node, by index. This
     * currently assumes that all nodes in the tree are
     * explicitly managed by JFC (and not by a virtual tree
     * where we supply the contents)
     *
     * @param index Zero-based index of child to return
     * @return The node at the requested index, or null
     */
    public TreeNode getChildAt( int index ) {
        TreeNode node = null;
        Debug.println( 9, "DirNode.getChildAt: <" +
                       getDN() + "> index " + index );

        /* Force collecting children, if not already done */
        int count = getChildCount();
        if ( count > super.getChildCount() ) {
            reload();
        }

        try {
            node = super.getChildAt( index );
        } catch ( Exception e ) {
            // Request for node outside of range
            Debug.println( "DirNode.getChildAt: " + count +
                           " children " +
                           "available, number " + index +
                           " requested: " + e );
            node = getBogusEntryObject();
        }
        Debug.println( 9, "DirNode.getChildAt: found <" +
                       ((DirNode)node).getDN() + ">" );
        return node;
    }

    /**
     * Report the number of children (containers only) of this
     * node
     *
     * @return The number of container nodes that are children
     * of this node
     */

    public int getChildCount() {
        if(_isBogus)
            return 0;

        // If we haven't checked for children yet...
        if ( !hasCheckedForChildren() ) {
            Debug.println( 9, "DirNode.getChildCount: <" +
                           getDN() + " > checking" );
            // Read the entry
            if ( !isLoaded() ) {
                load();
            }
            // Check if numsubordinates is there
            int count = getCountFromEntry();
            if ( count == 0 ) {
                _iChildren = 0;
            } else if ( ( count < 0 ) ||
                        !getModel().getAllowsLeafNodes() ) {
                // The count is -1 if the server has not
                // reported numsubordinates. If it is > 0
                // we still need to manually count the
                // children if we are only to show containers,
                // so do a brute-force count.
                _iChildren = countChildren(
                    getModel().getAllowsLeafNodes() );
            } else {
                // numsubordinates is present and we are
                // counting all children
                _iChildren = count;
            }
        } else {
            Debug.println( 9, "DirNode.getChildCount: <" +
                           getDN() + " > already checked" );
        }
        return _iChildren;
    }

    /**
     * Remove all children of this node
     */
    public void removeAllChildren() {
        _iChildren = 0;
        super.removeAllChildren();
    }

    /**
     * Check whether the node is a leaf node or not. Since this
     * is used by JTree to determine whether or not to put an
     * expander on the tree, return true if the node currently
     * has no children.
     *
     * @return <CODE>true</CODE> if the node is a leaf
     */
    public boolean isLeaf() {
        int count = getChildCount();
        Debug.println( 9, "DirNode.isLeaf: <" + getDN() +
                           ">  : " + count +
                       " children" );
        return ( count == 0 );
    }

    public String toString() {
        return "DirNode for <" + getDN() + ">";
    }

    /**
     * Report if the DN of a node matches the DN of one of
     * the immediate child nodes
     *
     * @param node A node to compare
     * @return <CODE>true</CODE> if one of the immediate child
     * nodes has the same DN
     */
    public boolean childExists( IDirNode node ) {
        DirNode ch;
        Enumeration e = children();
        while( e.hasMoreElements() ) {
            ch = (DirNode)e.nextElement();
            if ( ch.getDN().equals(node.getDN()) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Create a place-holder node
     *
     * @return A place-holder node
     */
    static public DirNode getBogusEntryObject() {
        DirNode bogus = new DirNode(true);
        bogus.setDN(BOGUS_LABEL);
        bogus.setName(BOGUS_LABEL);
        bogus.setIcon(BOGUS_ICON);
        return bogus;
    }

    static protected boolean isRootDSE( String dn ) {
        return ( (dn == null) || dn.equals("") );
    }

    protected String getChildFilter() {
        return getModel().getChildFilter();
    }

    // Properties file for this class
    protected static final String IMAGE_PATH = "com/netscape/management/client/images/";
    static ResourceSet _resource =new ResourceSet("com.netscape.management.client.components.components");
    private static final String _section = "dirBrowser";

    // Default image name for tree nodes
    static private String _defaultImageName =
        initDefaultIconName();
    static private String _defaultFolderImageName =
        initDefaultFolderIconName();

    // Full DN of this node
    private String _dn;
    // Display name
    private String _sDisplayName;
    // cn, if any
    private String _sCn = null;
    // flag to indicate if the node is loaded or not
    protected boolean _fLoaded = false;
    // Number of immediate children; -1 if not known
    protected int _iChildren = -1;
    // True if it can have children
    protected boolean _fContainer = false;
    // Hash code for the object classes the entry contains
    private long _objectCode = 0;
    // Object classes of this entry
    protected Hashtable _objectClasses = null;
    // The directory model
    private IDirModel _model = null;
    // Directory entry for this node
    protected LDAPEntry _entry = null;
    // Icon to show in tree
    private Icon _icon = null;
    // true if e.g. bad referral
    private boolean _isBogus = false;
    // Control to prevent referrals being returned
    private static LDAPControl _manageDSAITControl =
            new LDAPControl( LDAPControl.MANAGEDSAIT, true,
                             null );
    // Name of attribute containing the number of children
    protected static final String SUBORDINATE_ATTR =
        "numsubordinates";
    // Filter to return everything
    protected final static String _allFilter =
        "objectclass=*";
    // Attributes we always search for
    protected final static String[] _baseAttrs =
                 { "cn", SUBORDINATE_ATTR, "displayName",
                   "objectclass" };
    // Properties of a place-holder node
    private static final ImageIcon BOGUS_ICON = new RemoteImage(IMAGE_PATH + "error16.gif");
    private static final String BOGUS_LABEL = _resource.getString(_section, "error-label");
}
