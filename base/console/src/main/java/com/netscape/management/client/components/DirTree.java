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
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.tree.*;
import com.netscape.management.client.util.Debug;												
public class DirTree extends JTree
                     implements TreeSelectionListener,
                                MouseListener,
                                KeyListener {

    /**
     * Construct Tree using the data model specified.
     *
     * @param model A Directory model
     */
    public DirTree( IDirModel model ) {
        super( model );
        _treeRenderer = new TreePanelCellRenderer();
        _model = model;
        initialize();
    }

    /**
     * Default constructor for deserialization
     */
    public DirTree() {
        this( null );
    }


    /**
     *  Set up all special properties
     */
    protected void initialize() {
        // Lines between nodes, as in Windows
        putClientProperty( "JTree.lineStyle", "Angled" );
        // For now, single selection only
        getSelectionModel().setSelectionMode(
            TreeSelectionModel.SINGLE_TREE_SELECTION );
        addFocusListener(new FocusListener() {
            // this causes ALL tree nodes to repaint, which
            // is needed to change colors for selected tree
            // nodes
            public void focusGained(FocusEvent e) {
                JTree tree = (JTree)e.getSource();
                tree.validate();
                tree.repaint();
            }
            public void focusLost(FocusEvent e) {
                JTree tree = (JTree)e.getSource();
                tree.validate();
                tree.repaint();
            }
        });
        // Special cell renderer
        setCellRenderer(_treeRenderer);
        // Catch all events
        addTreeSelectionListener(this);
        addMouseListener(this);
        addKeyListener(this);

        ToolTipManager.sharedInstance().registerComponent(this);
    }

    /**
     * Set the model
     *
     * @param model the model
     */
    public void setModel( IDirModel model ) {
        super.setModel( model );
        _model = model;
    }

    /**
     * Adds a listener that is interested in receiving
     * DirNodeListener events.
     *
     * @param l An object interested in receiving
     * DirNodeListener events
     */
    public void addDirNodeListener( IDirNodeListener l ) {
        _listenerList.add( IDirNodeListener.class, l );
    }

    /**
     * Removes a listener that is interested in receiving
     * DirNodeListener events.
     *
     * @param l An object interested in receiving
     * DirNodeListener events
     */
    public void removeDirNodeListener( IDirNodeListener l ) {
        _listenerList.remove( IDirNodeListener.class, l );
    }

    /**
     * Dispatch selection events to listeners
     *
     * @param nodes Currently selected nodes
     */
    protected void select( IDirNode[] nodes ) {
        fireSelectionChanged( nodes );
    }

    /**
     * Dispatch "run" event to listeners
     *
     * @param nodes Currently selected nodes
     * @param param Optional additional event info
     */
    protected void run( IDirNode[] nodes, String param ) {
        fireActionInvoked( nodes, DirNodeEvent.RUN, param );
    }

    /**
     * Dispatch selection events to listeners
     *
     * @param nodes Currently selected nodes
     */
    protected void fireSelectionChanged( IDirNode[] nodes ) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for ( int i = listeners.length - 2; i >= 0; i -= 2 ) {
            if ( listeners[i] == IDirNodeListener.class ) {
                IDirNodeListener l =
                    (IDirNodeListener)listeners[i + 1];
                l.selectionChanged( nodes );
            }
        }
    }

    /**
     * Dispatch events to listeners
     *
     * @param nodes Currently selected nodes
     * @param id Identifier of the type of event
     * @param param Optional additional event info
     */
    protected void fireActionInvoked( IDirNode[] nodes,
                                      int id,
                                      String param ) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        DirNodeEvent e = null;
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for ( int i = listeners.length - 2; i >= 0; i -= 2 ) {
            if ( listeners[i] == IDirNodeListener.class ) {
                // Lazily create the event:
                if (e == null)
                    e = new DirNodeEvent( nodes, id, param );
                IDirNodeListener l =
                    (IDirNodeListener)listeners[i + 1];
                l.actionInvoked( e );
            }
        }
    }

    /**
     * Implements TreeSelectionListener. Called when an object
     * is selected in the tree.
     *
     * @param ev Event provided by JTree
     */
    public void valueChanged(TreeSelectionEvent ev) {
        Debug.println( 9, "Tree.valueChanged: " +
                       ev.getPath().getLastPathComponent() );
        IDirNode[] selection = getSelection();
        if ( selection != null ) {
            Debug.println( 9, "Tree.valueChanged: selection = " +
                           selection[0] );
            select( selection );
        }
    }

    /**
     * Implements MouseListener. Called when a mouse button is
     * pressed and released in the tree.
     *
     * @param e Mouse event
     */
    public void mouseClicked(MouseEvent e) {
        IDirNode[] selection = getSelection();
        if (selection != null) {
            if (e.getClickCount() == 2) { // double click
                run( selection, "" );
            }
        }
    }

    /**
     * Implements MouseListener. Called when a mouse button
     * is pressed in the tree.
     *
     * @param e Mouse event
     */
    public void mousePressed(MouseEvent e) {
        if ((_contextMenu != null) && (e.isPopupTrigger())) {
            if (_contextMenu.getComponentCount() > 0) {
                Component c = e.getComponent();
                Point p = c.getLocation();
                _contextMenu.show( c, e.getX() - p.x,
                                   e.getY() - p.y );
            }
        }
    }

    /**
     * Implements MouseListener.
     *
     * @param e Mouse event
     */
    public void mouseEntered(MouseEvent e) {
    }

    /**
     * Implements MouseListener.
     *
     * @param e Mouse event
     */
    public void mouseExited(MouseEvent e) {
    }

    /**
     * Implements MouseListener. Called when a mouse button is
     * released in the tree.
     *
     * @param e Mouse event
     */
    public void mouseReleased(MouseEvent e) {
        if ((_contextMenu != null) && (e.isPopupTrigger())) {
            if (_contextMenu.getComponentCount() > 0) {
                Component c = e.getComponent();
                Point p = c.getLocation();
                _contextMenu.show( c, e.getX() - p.x,
                                   e.getY() - p.y );
            }
        }
    }

    /**
     * Implements KeyListener
     *
     * @param e Key event
     */
    public void keyTyped(KeyEvent e) {
    }

    /**
     * Implements KeyListener. Called when a key is pressed.
     *
     * @param e Key event
     */
    public void keyPressed(KeyEvent e) {
        if (e.getKeyCode() == KeyEvent.VK_ENTER) {
            IDirNode[] selection = getSelection();
            if (selection != null) {
                run( selection, "" );
            }
        }
    }

    /**
     * Implements KeyListener. Called when a key is released.
     *
     * @param e Key event
     */
    public void keyReleased(KeyEvent e) {
    }

    /**
     * Returns array of selected nodes.
     *
     * @param return array of selected nodes.
     */
    public IDirNode[] getSelection() {
        IDirNode[] selection = null;
        TreePath path[] = getSelectionPaths();
        if ((path != null) && (path.length > 0)) {
            selection = new IDirNode[path.length];
            for (int index = 0; index < path.length; index++) {
                selection[index] =
                    (IDirNode)path[index].
                    getLastPathComponent();
            }
        }
        return selection;
    }

    /**
     * Make a node selected and visible
     *
     * @param node Node to make visible
     */
    public void setSelectedNode( IDirNode node ) {
        if ( node != null ) {
            TreePath path =
                new TreePath(
                    ((DefaultMutableTreeNode)node).getPath() );
            expandPath( path );
            makeVisible( path );
            scrollPathToVisible( path );
            repaint();
            setSelectionPath( path );
        }
    }

    protected IDirModel _model;
    protected TreeCellRenderer _treeRenderer;
    protected EventListenerList _listenerList =
        new EventListenerList();
    protected JPopupMenu _contextMenu = new JPopupMenu();
}
