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
import javax.swing.*;
import netscape.ldap.*;
import com.netscape.management.client.util.*;

/**
 * RootDirNode is the root node of a Directory tree
 *
 * @author  rweltman
 * @version %I%, %G%
 */
public class RootDirNode extends DirNode
                         implements Serializable {
    /**
     * Constructor of the entry object. It will not load the
     * directory information until later. This function will
     * just initialize the internal variables.
     *
     * @param model Content model.
     * @param displayName Name to use for rendering this node
     * @param showPrivateSuffixes <CODE>false</CODE> if only
     * public suffixes will be visible
     */
    public RootDirNode( IDirModel model,
                        String displayName,
                        boolean showPrivateSuffixes ) {
        super( model, "", displayName );
        _showPrivateSuffixes = showPrivateSuffixes;
        Debug.println(9, "RootDirNode.RootDirNode(3)");
    }

    /**
     * Constructor of the entry object. It will not load the
     * directory information until later. This function will
     * just initialize the internal variables.
     *
     * @param model Content model.
     * @param showPrivateSuffixes <CODE>false</CODE> if only
     * public suffixes will be visible
     */
    public RootDirNode( IDirModel model,
                        boolean showPrivateSuffixes ) {
        _showPrivateSuffixes = showPrivateSuffixes;
        Debug.println(9, "RootDirNode.RootDirNode(2): " +
                      "private = " + _showPrivateSuffixes);
        // Figure out a good display name for this node
        String displayName = "";
        if ( model != null ) {
            LDAPConnection ldc = model.getLDAPConnection();
            if ( ldc != null ) {
                displayName =
                    ldc.getHost() + ":" + ldc.getPort();
            }
        }
        initialize( model, "", displayName );
    }

    /**
     * Constructor of the entry object.
     *
     * @param model Content model.
     * @param entry LDAP entry.
     */
    public RootDirNode( IDirModel model,
                        LDAPEntry entry,
                        boolean showPrivateSuffixes ) {
        this( model, showPrivateSuffixes );
        Debug.println(9, "RootDirNode.DirNode(3a)");
        _entry = entry;
        initializeFromEntry( _entry );
    }

    /**
     * Initialize the entry object with a name and icon.
     *
     * @param model Content model.
     * @param dn DN of the Directory entry
     * @param displayName Name to use for rendering this node
     */
    protected void initialize( IDirModel model,
                               String dn,
                               String displayName ) {
        super.initialize( model, dn, displayName );
        setIcon(new RemoteImage(DirNode.IMAGE_PATH + "host.gif" ) );
        load();
    }

    /**
     *  Check if there are children to this node.
     */
    public void load() {
        Debug.println(9, "RootDirNode.load" );
        getChildList();
    }

    public boolean isLeaf() {
        return false;
    }

    /**
     * Expand a single "root" node
     */
    private DirNode getNode( String dn ) {
        Debug.println( 9, "DirNode.getNode: <" + dn + ">" );
        if ( isRootDSE( dn ) ) {
            return null;
        }
        DirNode node = null;
        Debug.println( "  NamingContext: " + dn );
        LDAPEntry entry = readEntry( dn, _baseAttrs );
        if ( entry == null ) {
            Debug.println( "  Read of <" + dn +
                           "> returned null" );
        } else {
            node = new DirNode( getModel(), entry );
        }
        // DS 4.0 doesn't report hierarchy correctly under
        // cn=config or cn=ldbm yet... ???
        if ( dn.equalsIgnoreCase("cn=config") ||
             dn.equalsIgnoreCase("cn=ldbm") ) {
            node.setIcon(((DirModel)getModel()).checkIcon( _objectClasses, false ));
        }
        return node;
    }

    /**
     * create all the one level depth sub nodes defined in an
     * enumeration of DNs.
     */
    protected void addSuffixNodes( Enumeration e ) {
        while ( e.hasMoreElements() ) {
            String dn = (String)e.nextElement();
            Debug.println( "RootDirNode.addSuffixNodes: <" +
                           dn + ">" );
            DirNode node = getNode( dn );
            if ( node != null ) {
                add( node );
            }
        }
    }

    /**
     *  Create a vector of all the one level depth sub nodes:
     *  public and possibly private suffixes. Override DirNode.
     */
    protected Vector getChildList() {
        Debug.println( "RootDirNode.getChildList" );
        removeAllChildren();

        // Root, above all suffixes. Read from the root DSE.
        String[] attrs = { "namingcontexts" };
        LDAPEntry entry = readEntry( "", attrs );
        if ( entry == null ) {
            Debug.println( "RootDirNode.expandRoot: readEntry " +
                           "returned null" );
            return null;
        }
        _objectClasses = checkObjectClasses( entry );
        LDAPAttribute attr = entry.getAttribute( attrs[0] );
        // The attribute's values are the various suffixes
        if ( attr == null ) {
            Debug.println( "RootDirNode.getChildList: <" +
                           attrs[0] + "> returned null" );
            return null;
        }

        addSuffixNodes( attr.getStringValues() );

        if ( _showPrivateSuffixes ) {
            // Get private naming contexts
            attrs[0] = _privateSuffixAttr;
            entry = readEntry( _configDN, attrs );
            if ( entry == null ) {
                Debug.println( "RootDirNode.getChildList: <" +
                               _configDN + "> returned null" );
            } else {
                attr = entry.getAttribute( attrs[0] );
                // The attribute's values are the various
                // suffixes
                if ( attr != null ) {
                    addSuffixNodes( attr.getStringValues() );
                }
            }
        }

        _fLoaded = true;
        _fContainer = true;
        _iChildren = children.size();
        Debug.println( "RootDirNode.getChildList found " +
                       _iChildren + " searchable suffixes" );
        return null;
    }

    public void initializeFromEntry( LDAPEntry entry ) {
        Icon image = getIcon();
        super.initializeFromEntry( entry );
        setIcon( image );
    }

    // Set this to false to NOT show private suffixes
    private boolean _showPrivateSuffixes = true;

    // Entry that stores private suffixes
    private static final String _configDN = "cn=config";
    // Attribute containing private suffixes
    private static final String _privateSuffixAttr =
        "nsslapd-privatenamespaces";
}
