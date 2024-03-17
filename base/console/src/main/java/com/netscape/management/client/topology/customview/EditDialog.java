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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.tree.*;
import com.netscape.management.client.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.topology.*;
import com.netscape.management.client.util.*;

/**
 * Edit dialog for custom view management
 */
public class EditDialog extends GenericDialog
{
    JTree defaultTree;
    JTree customTree;
    TreeModel customTreeModel;
    JPanel mainPanel;
	private JTextField viewNameField;

    static String i18n(String id) {
        return TopologyInitializer._resource.getString("customview", id);
    }

    /**
      * constructor
      *
      * @param frame parent frame
      * @param defaultTreeModel default topology tree model
      * @param customTreeModel the new tree model for the custom view
      * @param viewName name of the custom view
      */
    public EditDialog(JFrame frame, TreeModel defaultTreeModel,
            TreeModel customTreeModel, String viewName) {
        super(frame, i18n("EditView"), OK | CANCEL | HELP);
        this.customTreeModel = customTreeModel;
        getContentPane().add(createDialogPanel(defaultTreeModel, customTreeModel, viewName));
    }

    /**
      * create the dialog internal content.
      *
      * @param defaultTreeModel default topology tree model
      * @param customTreeModel the new custom tree model
      * @param viewName name of the custom view
      */
    private JComponent createDialogPanel(TreeModel defaultTreeModel,
            TreeModel customTreeModel, String viewName) {
        JPanel leftPanel = new JPanel(new GridBagLayout());
        JLabel defaultViewLabel = new JLabel(i18n("DefaultView"));
        UITools.constrain(leftPanel, defaultViewLabel, 0, 0, 1, 1, 1.0,
                0.0, GridBagConstraints.EAST,
                GridBagConstraints.HORIZONTAL, 0, 0, COMPONENT_SPACE, 0);

        JScrollPane defaultTreeScrollPanel = new JScrollPane();
        defaultTreeScrollPanel.setBorder(UITools.createLoweredBorder());
        defaultTree = new JTree(defaultTreeModel);
        defaultTree.setToolTipText(i18n("defaultTree_tt"));
        defaultTree.setRootVisible(false);
        defaultTree.setShowsRootHandles(false);
        defaultTree.setCellRenderer(new ResourceCellRenderer());
        defaultTree.expandRow(0);
        //defaultTree.setPreferredSize(new Dimension(200, 300));
        defaultTreeScrollPanel.getViewport().add(defaultTree);

        UITools.constrain(leftPanel, defaultTreeScrollPanel, 0, 1, 1,
                1, 1.0, 1.0, GridBagConstraints.EAST,
                GridBagConstraints.BOTH, 0, 0, 0, 0);
        JButton copyButton = ButtonFactory.createButton(i18n("Copy"), new CopyButtonActionListener(),"COPY");
        copyButton.setToolTipText(i18n("copy_tt"));
        copyButton.setIcon(ButtonFactory.RIGHT_ICON);
        copyButton.setHorizontalTextPosition(JButton.LEFT);
        copyButton.setEnabled(false);
        defaultTree.addTreeSelectionListener(
                new ButtonTreeSelectionListener(copyButton));

        // -----------------------------------------------------------------------------
        JPanel rightPanel = new JPanel(new GridBagLayout());
        viewNameField = new JTextField(viewName);
        viewNameField.setToolTipText(i18n("viewName_tt"));
        UITools.constrain(rightPanel, viewNameField, 1, 0, 1, 1, 1.0, 0.0,
                GridBagConstraints.EAST,
                GridBagConstraints.HORIZONTAL, 0, 0, COMPONENT_SPACE, 0);
        
        customTreeModel.addTreeModelListener(new TreeModelListener()
            {
                public void treeNodesChanged(TreeModelEvent e)
                {
                }
                public void treeNodesInserted(TreeModelEvent e)
                {
                }
                public void treeNodesRemoved(TreeModelEvent e)
                {
                }
                public void treeStructureChanged(TreeModelEvent e)
                {
                    setOKButtonEnabled(customTree.getRowCount() > 0);
                }
            });
        
        customTree = new JTree(customTreeModel);
        customTree.setToolTipText(i18n("customTree_tt"));
        customTree.setRootVisible(false);
        customTree.setShowsRootHandles(false);
        customTree.setCellRenderer(new ResourceCellRenderer());
        setOKButtonEnabled(customTree.getRowCount() > 0);
        JScrollPane treeScrollPanel = new JScrollPane(customTree);

        UITools.constrain(rightPanel, treeScrollPanel, 1, 1, 1, 1, 1.0,
                1.0, GridBagConstraints.EAST, GridBagConstraints.BOTH,
                0, 0, 0, 0);

        JButton removeButton = ButtonFactory.createButton(i18n("RemoveView"), new RemoveButtonActionListener(),"REMOVE");
        removeButton.setToolTipText(i18n("removeView_tt"));
        removeButton.setIcon(ButtonFactory.LEFT_ICON);
        removeButton.setHorizontalTextPosition(JButton.RIGHT);
        removeButton.setEnabled(false);
        
        ButtonFactory.resizeButtons(copyButton, removeButton);
        customTree.addTreeSelectionListener(new ButtonTreeSelectionListener(removeButton));

        // -----------------------------------------------------------------------------
        JPanel buttonPanel = new JPanel(new GridBagLayout());
        UITools.constrain(buttonPanel, new JPanel(), 0, 0, 1, 1, 0.0,
                1.0, GridBagConstraints.NORTH,
                GridBagConstraints.VERTICAL, 0, 0, 0, 0);

        UITools.constrain(buttonPanel, copyButton, 0, 1, 1, 1, 1.0,
                0.0, GridBagConstraints.SOUTH,
                GridBagConstraints.HORIZONTAL, 0, 0, COMPONENT_SPACE, 0);

        UITools.constrain(buttonPanel, removeButton, 0, 2, 1, 1, 1.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        UITools.constrain(buttonPanel, new JPanel(), 0, 3, 1, 1, 0.0,
                1.0, GridBagConstraints.NORTH,
                GridBagConstraints.VERTICAL, 0, 0, 0, 0);

        // -----------------------------------------------------------------------------
        mainPanel = new JPanel(new GridBagLayout());
        UITools.constrain(mainPanel, leftPanel, 0, 0, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, COMPONENT_SPACE);

        UITools.constrain(mainPanel, buttonPanel, 1, 0, 1, 1, 0.0,
                1.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

        UITools.constrain(mainPanel, rightPanel, 2, 0, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                COMPONENT_SPACE, COMPONENT_SPACE, 0);

        mainPanel.setPreferredSize(new Dimension(500, 250));
        return mainPanel;
    }

    /**
      * inner class to handle different button status when an item in the tree is selected
      */
    class ButtonTreeSelectionListener implements TreeSelectionListener {
        JButton _button;

        /**
         * constructor
         *
         * @param button button to be listened.
         */
        public ButtonTreeSelectionListener(JButton button) {
            _button = button;
        }

        /**
          * change the button status according to the item selection
          */
        public void valueChanged(TreeSelectionEvent e) {
            JTree t = (JTree) e.getSource();
            int c = t.getSelectionCount();
            _button.setEnabled(c > 0);
        }
    }

    /**
      * inner class for the copy button action
      */
    class CopyButtonActionListener implements ActionListener {
        /**
          * copy the current selected item when the copy button is pressed.
          *
          * @param e event
          */
        public void actionPerformed(ActionEvent e) {
            TreePath path[] = defaultTree.getSelectionPaths();
            for(int i = 0; i < path.length; i++)
            {
                ResourceObject obj =
                        (ResourceObject) path[i].getLastPathComponent();
                if (obj != null) {
                    TreeModel treeModel = customTreeModel;
                    ResourceObject root = (ResourceObject) treeModel.getRoot();
                    if (obj instanceof Cloneable) {
                        root.add((MutableTreeNode) obj.clone());
                        if (treeModel instanceof ResourceModel)
                            ((ResourceModel) treeModel).
                                    fireTreeStructureChanged(
                                    (ResourceObject) root);
                        mainPanel.repaint();
                        mainPanel.validate();
                    } else
                        Debug.println("Tree Node not Clonable: " + obj);
                }
            }
        }
    }

    /**
      * inner class for remove button action
      */
    class RemoveButtonActionListener implements ActionListener {
        /**
          * remove the selected custom view when the remove button is pressed
          *
          * @param e event
          */
        public void actionPerformed(ActionEvent e) {
            TreePath path[] = customTree.getSelectionPaths();
            for(int i = 0; i < path.length; i++)
            {
                DefaultMutableTreeNode obj =
                        (DefaultMutableTreeNode) path[i].getLastPathComponent();
                if (obj != null) {
                    DefaultMutableTreeNode parent =
                            (DefaultMutableTreeNode) obj.getParent();
                    parent.remove(obj);
                    Object treeModel = customTreeModel;
                    if (treeModel instanceof ResourceModel)
                        ((ResourceModel) treeModel). fireTreeStructureChanged(
                                (ResourceObject) parent);
                }
            }
        }
    }

    /**
      * Called when HELP button is pressed
      */
    protected void helpInvoked() {
        ConsoleHelp.showContextHelp("customview-EditDialogHelp");
    }
	
	/**
	 * Gets the view name
	 * 
	 * @return view name
	 */
	public String getViewName()
	{
		return viewNameField.getText().trim();
	}
	
	public void setNameFieldFocused()
	{
		setFocusComponent(viewNameField);
	}
}
