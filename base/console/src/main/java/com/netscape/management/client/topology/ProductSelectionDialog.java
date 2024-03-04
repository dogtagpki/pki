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

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.client.util.*;


/**
 * Dialog which presents the servers available in the Admin Group matching
 * a particular criteria. Two uses of this dialog include presenting a list
 * of servers for migration and cloning.
 *
 * @author  phlee
 */

public class ProductSelectionDialog extends AbstractModalDialog {

    // This dialog's configuration.
    public static final int DEFAULT_CONFIGURATION = 0;
    public static final int FOR_MIGRATION = 1;
    public static final int FOR_CLONING = 2;
    public static final int FOR_CREATION = 3;

    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");

    private JList _productList;
    private String[]_productInfo; // Info for tool tips
    private JLabel _prompt;
    private int _task; // What this dialog is for (migration, cloning, or creation)
    private Help _helpSession; // For invoking help.
    private String _defaultTitle;
    private String _defaultPrompt;
    private String _defaultActionLabel;


    /**
     * constructor for the dialog
     */
    public ProductSelectionDialog(Frame parent) {
        this(parent, DEFAULT_CONFIGURATION);
    }


    /**
      * constructor for the dialog
      */
    public ProductSelectionDialog(Frame parent, int task) {
        // This is a modal dialog to support synchronous processing, i.e.,
        // usage involves displaying the dialog, user interacting with the
        // dialog, and the code retrieving the data from the dialog before
        // continuing.
        super(parent, "");

        _task = task;

        _helpSession = new Help(_resource);

        _defaultTitle = _resource.getString("ProductSelectionDialog", "DefaultTitle");
        _defaultPrompt =
                _resource.getString("ProductSelectionDialog", "DefaultPrompt");
        _defaultActionLabel =
                _resource.getString("ProductSelectionDialog", "DefaultActionLabel");

        _prompt = new JLabel();
        configure(_task); // Set the correct labels for title, prompt, and action button.

        _productInfo = null;
        _productList = new JList();
        _productList.addMouseMotionListener(
                new DialogMouseMotionListener());
        _productList.addListSelectionListener(
                new DialogListSelectionListener());
        _productList.setSelectionMode(
                ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        _prompt.setLabelFor(_productList);
        JScrollPane listScroller = new JScrollPane();
        listScroller.getViewport().setView(_productList);
        listScroller.setBorder(UIManager.getBorder("Table.scrollPaneBorder"));

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(panel, _prompt, 0, 0,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        GridBagUtil.constrain(panel, listScroller, 0, 1,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 1.0, 1.0,
                GridBagConstraints.WEST, GridBagConstraints.BOTH, 0,
                0, 0, 0);

        setPanel(panel);

        setSize(475, 300);
        setMinimumSize(475, 300);
    }


    public void configure(int task) {
        _task = task;
        if (task == FOR_MIGRATION) {
            setTitle(_resource.getString("ProductSelectionDialog", "MigrateTitle"));
            _prompt.setText(
                    _resource.getString("ProductSelectionDialog", "MigratePrompt"));
            setOKButtonText(
                    _resource.getString("ProductSelectionDialog", "MigrateButtonLabel"));
        } else if (task == FOR_CLONING) {
            setTitle(_resource.getString("ProductSelectionDialog", "CloneTitle"));
            _prompt.setText(
                    _resource.getString("ProductSelectionDialog", "ClonePrompt"));
            setOKButtonText(
                    _resource.getString("ProductSelectionDialog", "CloneButtonLabel"));
        } else if (task == FOR_CREATION) {
            setTitle(_resource.getString("ProductSelectionDialog", "CreateTitle"));
            _prompt.setText(
                    _resource.getString("ProductSelectionDialog", "CreatePrompt"));
            setOKButtonText(
                    _resource.getString("ProductSelectionDialog", "CreateButtonLabel"));
        } else {
            setTitle(_defaultTitle);
            _prompt.setText(_defaultPrompt);
            setOKButtonText(_defaultActionLabel);
        }

        // Resize the dialog as necessary to refresh labels.
        setOKButtonEnabled(false);
    }


    /**
      * The deprecation warning for this is erroneous. This method
      * overrides Dialog.show(). It is safe to ignore warning.
      */
    public void show() {
        ModalDialogUtil.setDialogLocation(this, null);
        // Clear any selection before displaying the dialog.
        // Desired side effect is to disable the action button.
        _productList.clearSelection();
        super.show();
    }


    public int getTask() {
        return _task;
    }


    public int[] getSelectedIndices() {
        return _productList.getSelectedIndices();
    }


    public Object[] getSelectedValues() {
        return _productList.getSelectedValues();
    }


    /**
      * Set the product list. Set the reference to any previous product
      * information as invalid.
      *
      * @param productList  products to display in the selection list
      */
    public void setProductList(String[] productList) {
        _productList.setListData(productList);
        _productInfo = null;
    }


    /**
      * Set the list as well as the information to display in tool tips.
      *
      * @param productList  products to display in the selection list
      * @param productInfo  array of product information strings
      */
    public void setProductList(String[] productList, String[] productInfo) {
        _productList.setListData(productList);
        setProductInfo(productInfo);
    }


    /**
      * Set the product information to display in tool tips.
      *
      * @param productInfo  array of product information strings
      */
    public void setProductInfo(String[] productInfo) {
        _productInfo = productInfo;
    }


    /**
      * Implements the method to handle help event.
      */
    public void helpInvoked() {
        if (_task == FOR_MIGRATION) {
            _helpSession.contextHelp("topology", "psd-migrate");
        } else if (_task == FOR_CLONING) {
            _helpSession.contextHelp("topology", "psd-clone");
        } else if (_task == FOR_CREATION) {
            _helpSession.contextHelp("topology", "psd-create");
        } else {
            Debug.println(
                    "ERROR ProductSelectionDialog.help: no help available for dialog task: " +
                    _task);
        }
    }


    /**
      * Inner class used to handle list mouse motion events.
      */
    class DialogMouseMotionListener implements MouseMotionListener {
        public void mouseDragged(MouseEvent e) {
            if (_productInfo == null) {
                return;
            }
            int index = _productList.locationToIndex(e.getPoint());
            if (index >= 0 && index < _productInfo.length) {
                _productList.setToolTipText((String)_productInfo[index]);
            }
        }

        public void mouseMoved(MouseEvent e) {
            if (_productInfo == null) {
                return;
            }
            int index = _productList.locationToIndex(e.getPoint());
            if (index >= 0 && index < _productInfo.length) {
                _productList.setToolTipText((String)_productInfo[index]);
            }
        }
    }


    /**
      * Inner class used to handle window events.
      */
    class DialogListSelectionListener implements ListSelectionListener {
        public void valueChanged(ListSelectionEvent e) {
            int[] selection = _productList.getSelectedIndices();
            if (selection.length == 0) {
                ProductSelectionDialog.this.setOKButtonEnabled(false);
            } else {
                // Enable the action button if any item is selected.
                ProductSelectionDialog.this.setOKButtonEnabled(true);
            }
        }
    }
}
