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

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.Hashtable;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import javax.swing.border.BevelBorder;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.client.util.Help;
import com.netscape.management.client.util.JButtonFactory;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.client.util.SingleByteTextArea;
import com.netscape.management.client.util.SingleByteTextField;
import com.netscape.management.nmclf.SuiConstants;

/**
 * A general configurational panel to edit attributes. Inside NodeDataPanel, it will
 * display a set of NodeData objects. The node data object can be either editable or
 * non-editable.
 */
public class NodeDataPanel extends JPanel implements SuiConstants,
                                                     SwingConstants {
    public static String ID_OPEN = "ID_OPEN";

    private INodeInfo _nodeInfo;
    private JButton _editButton;
    private JButton _okButton;
    private JButton _cancelButton;
    private JButton _helpButton;
    private Box _buttonPanel;
    private Component _helpHorizontalSpace = Box.createHorizontalStrut(2*COMPONENT_SPACE);
    private Component _horizontalSpace = Box.createHorizontalStrut(COMPONENT_SPACE);
    private EditableNodeData _editableArray[];
    private Hashtable _valueTable = new Hashtable();
    private JLabel headingLabel = new JLabel();
    private ChangeKeyListener _keyChangeListener = new ChangeKeyListener();
    private JScrollPane _scrollPane;
    private String _title;
    private NodeDataChangeListener _changeListener;
    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");
    private String helpProduct = null;
    private String helpTopic = null;

    /**
     * constructor
     *
     * @param icon display icon for the panel
     * @param title display title for the panel. usually the name of the node.
     * @param nodeInfo a the resource object node information
     */
    public NodeDataPanel(Icon icon, String title, INodeInfo nodeInfo) {
        this(icon, title, nodeInfo, false, true);
    }

    /**
     * Constructor with show open button option.
     *
     * @param icon display icon for the panel
     * @param title display title for the panel. usually the name of the node.
     * @param nodeInfo a the resource object node information
     * @param showOpenButton if true, the panel will have a "Open" button to let the user
     *                       edit the attributes.
     */
    public NodeDataPanel(Icon icon, String title, INodeInfo nodeInfo,
                         boolean showOpenButton) {
        this(icon, title, nodeInfo, showOpenButton, true);
    }

    /**
     * Constructor with show open and edit button options.
     *
     * @param icon display icon for the panel
     * @param title display title for the panel. usually the name of the node.
     * @param nodeInfo a the resource object node information
     * @param showOpenButton if true, the panel will have a "Open" button to let the user
     *                       edit the attributes.
     * @param isEditable if true, the panel will have a "Edit" button
     */
    public NodeDataPanel(Icon icon, String title, INodeInfo nodeInfo,
                         boolean showOpenButton, boolean isEditable) {
        _nodeInfo = nodeInfo;
        setTitle(_title = title);
        if(isEditable)
            isEditable = TopologyInitializer.canEditTopology();
        createPanel(icon, nodeInfo, showOpenButton, isEditable);
        setMinimumSize(new Dimension(1, 1));

        //nodeInfo.addChangeListener(new NodeDataChangeListener());
        _changeListener = new NodeDataChangeListener();
        addAncestorListener(_ancestorListener);
    }

    /**
     * Ancestor events are used for the proper registering/unregistering for NodeDataChange
     * events. This prevents memory leaks.
     */
    AncestorListener _ancestorListener = new AncestorListener() {
            public void ancestorAdded(AncestorEvent e) {
                Debug.println("topology.NodeDataPanel ancestorAdded() adds Change Listener");
                _nodeInfo.addChangeListener(_changeListener);
            }

            public void ancestorRemoved(AncestorEvent e) {
                Debug.println("topology.NodeDataPanel ancestorRemoved() removes Change Listener");
                _nodeInfo.removeChangeListener(_changeListener);
            }

            public void ancestorMoved(AncestorEvent e) {}
        };

    /**
     * set the title of the panel
     *
     * @param title title of the panel
     */
    public void setTitle(String title) {
        headingLabel.setText(title);
        if (headingLabel.getParent() != null) {
            if (headingLabel.getParent().getParent() != null) {
                headingLabel.getParent().invalidate();
                headingLabel.getParent().getParent().validate();
            } else {
                headingLabel.getParent().validate();
            }
        }
        headingLabel.repaint();
    }

	/**
	 * Sets help context-sensitive help info for this panel.
	 * When the Help button is pressed, the help viewer is launched
	 * with these parameters.
	 *
	 * @param productID		the product identifier, which corresponds to the manual directory on the back-end
	 * @param topic			the help topic contained in tokens.map
	 */
    public void setHelpTopic(String productID, String topic)
    {
        helpProduct = productID;
        helpTopic = topic;
    }

	/**
	 * Returns the help topic used for this panel.
	 *
	 * @return the string that is help token for this dialog.
	 * @see #setHelpTopic
	 */
	public String getHelpTopic()
	{
		return helpTopic;
	}

    /**
     * create the panel internal control
     *
     * @param icon panel's icon
     * @param nodeInfo The node information data structure
     * @param showOpenButton whether we need to display the "open" button or not.
     */
    protected JPanel createPanel(Icon icon, INodeInfo nodeInfo,
                                 boolean showOpenButton, boolean isEditable) {
        JPanel panel = this; //new JPanel();
        panel.setLayout(new GridBagLayout());
        Border spacingBorder =
            BorderFactory.createEmptyBorder(VERT_WINDOW_INSET,
                                            HORIZ_WINDOW_INSET, VERT_WINDOW_INSET, HORIZ_WINDOW_INSET);
        Border etchedBorder = BorderFactory.createEtchedBorder();
        panel.setBorder( BorderFactory.createCompoundBorder(etchedBorder,
                                                            spacingBorder));

        headingLabel.setIcon(icon);
        headingLabel.setFont(UIManager.getFont("Title.font"));
        JPanel headingPanel = new JPanel(new BorderLayout());
        headingPanel.add(BorderLayout.WEST, headingLabel);

        if (showOpenButton) {
            JButton openButton =
                JButtonFactory.create(_resource.getString("General","open"),
                                      new OpenButtonActionListener(),"OPEN");
            openButton.setToolTipText(_resource.getString("General","open_tt"));
            JButtonFactory.resize(openButton);
            headingPanel.add(BorderLayout.EAST, openButton);
        }

        GridBagUtil.constrain(panel, headingPanel, 0,
                              GridBagConstraints.RELATIVE, 1, 1, 1.0, 0.0,
                              GridBagConstraints.EAST,
                              GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        JSeparator sep = new JSeparator();
        sep.setMinimumSize(sep.getPreferredSize());
        sep.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));
        GridBagUtil.constrain(panel, sep, 0,
                              GridBagConstraints.RELATIVE, 1, 1, 1.0, 0.0,
                              GridBagConstraints.WEST,
                              GridBagConstraints.HORIZONTAL, COMPONENT_SPACE, 0,
                              DIFFERENT_COMPONENT_SPACE, 0);

        JPanel scrollablePanel = new JPanel(new GridBagLayout());
        Vector editableVector = new Vector();
        int entryCount = nodeInfo.getNodeDataCount();
        for (int i = 0; i < entryCount; i++) {
            NodeData entry = nodeInfo.getNodeData(i);
            Object value = entry.getValue();
            if (value == null)
                value = "";
            if (value instanceof String) {
                JLabel nameLabel = new JLabel(entry.getName() + ":");
                GridBagUtil.constrain(scrollablePanel, nameLabel, 0,
                                      GridBagConstraints.RELATIVE, 1, 1, 0.0, 0.0,
                                      GridBagConstraints.NORTHEAST,
                                      GridBagConstraints.NONE, 0, 0,
                                      COMPONENT_SPACE, COMPONENT_SPACE);

                JComponent valueLabel;
				if (i == 1) {
					if (entry.is7Bit())
						valueLabel = new SingleByteTextArea((String) value);
					else
						valueLabel = new JTextArea((String) value);
					((JTextArea)valueLabel).setEditable(false);
				} else {
					if (entry.is7Bit()) {
						valueLabel = new SingleByteTextField();
						((JTextField)valueLabel).setText((String)value);
					} else {
						valueLabel = new JTextField((String) value);
					}
					((JTextField)valueLabel).setEditable(false);
                    ((JTextField)valueLabel).setBackground(UIManager.getColor("control"));
                    ((JTextField)valueLabel).select(0, 0);
                    ((JTextField)valueLabel).setBorder(BorderFactory.createEmptyBorder());
                    ((JTextField)valueLabel).setMargin(new Insets(0, 0, 0, 0));
				}
                nameLabel.setLabelFor(valueLabel);

                _valueTable.put(entry.getID(), valueLabel);
                valueLabel.setBackground(UIManager.getColor("control"));
                GridBagUtil.constrain(scrollablePanel, valueLabel, 1,
                                      GridBagConstraints.RELATIVE, 1, 1, 1.0, 0.0,
                                      GridBagConstraints.WEST,
                                      GridBagConstraints.HORIZONTAL, 0, 0,
                                      COMPONENT_SPACE, 0);
                if (entry.isEditable())
                    editableVector.addElement(
                                              new EditableNodeData(entry.getID(),
                                                                   entry.getName(), valueLabel));
            } else if (value instanceof Component) {
                String sName = entry.getName();
                boolean fAddName = false;
                if ((sName != null) && (!sName.equals(""))) {
                    JLabel nameLabel = new JLabel(entry.getName() + ":");
                    nameLabel.setLabelFor((Component)value);
                    GridBagUtil.constrain(scrollablePanel, nameLabel,
                                          0, GridBagConstraints.RELATIVE, 1, 1, 0.0,
                                          0.0, GridBagConstraints.NORTHEAST,
                                          GridBagConstraints.NONE, 0, 0,
                                          COMPONENT_SPACE, COMPONENT_SPACE);
                    fAddName = true;
                }

                GridBagUtil.constrain(scrollablePanel,
                                      (Component) value, fAddName ? 1 : 0,
                                      GridBagConstraints.RELATIVE, fAddName ? 1 : 2,
                                      1, 1.0, 0.0,
                                      fAddName ? GridBagConstraints.WEST :
                                      GridBagConstraints.EAST,
                                      GridBagConstraints.HORIZONTAL, 0, 0,
                                      COMPONENT_SPACE, 0);
                if (entry.isEditable()) {
                    ((Component) value).setEnabled(false);
                    editableVector.addElement(
                                              new EditableNodeData(entry.getID(),
                                                                   entry.getName(), (Component) value));
                }
            } else {
                Debug.println( "NodeDataPanel: unsupported NodeData type " +
                               value);
            }
        }
        _editableArray = new EditableNodeData[editableVector.size()];
        editableVector.copyInto(_editableArray);

        GridBagUtil.constrain(scrollablePanel, new JPanel(), 0,
                              GridBagConstraints.RELATIVE, 2, 1, 1.0, 1.0,
                              GridBagConstraints.SOUTHWEST, GridBagConstraints.BOTH,
                              0, 0, 0, 0);

        _scrollPane = new JScrollPane(scrollablePanel);
        _scrollPane.addComponentListener(
                                         new ScrollPaneComponentListener());
        _scrollPane.setBorder(new EmptyBorder(0, 0, 0, 0));
        _scrollPane.setHorizontalScrollBarPolicy(
                                                 ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        _scrollPane.setVerticalScrollBarPolicy(
                                               ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        GridBagUtil.constrain(panel, _scrollPane, 0,
                              GridBagConstraints.RELATIVE, 1, 1, 1.0, 1.0,
                              GridBagConstraints.NORTH,
                              GridBagConstraints.BOTH, 0, 0, 0, 0);

        if (editableVector.size() > 0) {
            _buttonPanel = new HorizontalButtonPanel(isEditable);
            GridBagUtil.constrain(panel, _buttonPanel, 0,
                                  GridBagConstraints.RELATIVE, 1, 1, 1.0, 0.0,
                                  GridBagConstraints.NORTHWEST,
                                  GridBagConstraints.HORIZONTAL,
                                  DIFFERENT_COMPONENT_SPACE, 0, 0, 0);
        }
        return panel;
    }

    class ScrollPaneComponentListener extends ComponentAdapter {
        // 322719: validate manually else scroll bars appears when they shouldn't
        public void componentResized(ComponentEvent e) {
            validate();
            repaint();
        }
    }

    class HorizontalButtonPanel extends Box {
        HorizontalButtonPanel(boolean isEditable) {
            super(BoxLayout.X_AXIS);
            Vector v = new Vector();

            this.add(Box.createHorizontalGlue());

            _editButton = JButtonFactory.create(_resource.getString("General","Edit"),
                                                new EditButtonListener(), "EDIT");
            _editButton.setToolTipText(_resource.getString("General","Edit_tt"));
 			_editButton.requestFocus();
            if (isEditable) {
                this.add(_editButton);
                v.addElement(_editButton);
            }
            _okButton =
                JButtonFactory.createOKButton(new OKButtonListener());
            _okButton.setToolTipText(_resource.getString("General","OK_tt"));
            v.addElement(_okButton);

            _cancelButton = JButtonFactory.createCancelButton(
                                                              new CancelButtonListener());
            _cancelButton.setToolTipText(_resource.getString("General","Cancel_tt"));
            v.addElement(_cancelButton);

			this.add(_helpHorizontalSpace);
			_helpButton = JButtonFactory.createHelpButton(new ActionListener(){
                    public void actionPerformed(ActionEvent e){
                        helpInvoked();}});
			this.add(_helpButton);
			v.addElement(_helpButton);

            JButton[] buttonGroup = new JButton[v.size()];
            v.copyInto(buttonGroup);
            if (buttonGroup != null) {
                JButtonFactory.resize(buttonGroup);
            }
        }
    }

    private void removeEditButton() {
        _buttonPanel.remove(_editButton);
		_buttonPanel.remove(_helpHorizontalSpace);
		_buttonPanel.remove(_helpButton);
        _buttonPanel.add(_okButton);
		setDefaultButton(_okButton);
        _buttonPanel.add(_horizontalSpace);
        _buttonPanel.add(_cancelButton);
		_buttonPanel.add(_helpHorizontalSpace);
        _buttonPanel.add(_helpButton);
        validate();
        repaint();
    }

    private void addEditButton() {
        _buttonPanel.remove(_okButton);
        _buttonPanel.remove(_horizontalSpace);
        _buttonPanel.remove(_cancelButton);
		_buttonPanel.remove(_horizontalSpace);
		_buttonPanel.remove(_helpButton);
        _buttonPanel.add(_editButton);
		_editButton.requestFocus();
		_buttonPanel.add(_helpHorizontalSpace);
		_buttonPanel.add(_helpButton);

        validate();
        repaint();
    }

	/**
	 * Sets initial default button (button pressed on enter).
	 */
	public void setDefaultButton(JButton button) {
		getRootPane().setDefaultButton(button);
	}

    class EditButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            for (int i = 0; i < _editableArray.length; i++) {
                _editableArray[i].actionEdit();
            }
            _scrollPane.setVerticalScrollBarPolicy(
                                                   ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER);
            removeEditButton();
        }
    }

    class OKButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            for (int i = 0; i < _editableArray.length; i++) {
                _editableArray[i].actionOK();
                _nodeInfo.actionNodeDataChanged(_editableArray[i]);
            }
            _scrollPane.setVerticalScrollBarPolicy(
                                                   ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
            addEditButton();
        }
    }

    class CancelButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            for (int i = 0; i < _editableArray.length; i++) {
                _editableArray[i].actionCancel();
            }
            _scrollPane.setVerticalScrollBarPolicy(
                                                   ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
            addEditButton();
        }
    }

    class EditableNodeData extends NodeData {
        Component _component = null;
        Object _originalValue = null;

        public EditableNodeData(String id, String name,
                                Component component) {
            super(id, name, null, true);
            _component = component;

            if (_component instanceof JTextArea) {
                JTextArea textArea = (JTextArea)_component;
                textArea.setWrapStyleWord(true);
                textArea.setLineWrap(true);
                textArea.addKeyListener(_keyChangeListener);
			} else if ((_component instanceof JTextField) &&
					   !(_component instanceof JPasswordField)) {
                JTextField textField = (JTextField)_component;
                textField.addKeyListener(_keyChangeListener);
            }
        }

        private void setEditable(boolean isEditable) {
            if (!isEditable) {
                if (_component instanceof JTextArea) {
                    JTextArea textArea = (JTextArea)_component;
                    textArea.setEditable(false);
                    textArea.setBackground(UIManager.getColor("control"));
                    textArea.setSelectionColor(UIManager.getColor("control"));
                    textArea.select(0, 0);
                    textArea.setBorder(BorderFactory.createEmptyBorder());
                    textArea.setMargin(new Insets(0, 0, 0, 0));
				} else if ((_component instanceof JTextField) &&
						   !(_component instanceof JPasswordField)) {
					JTextField textField = (JTextField)_component;
                    textField.setEditable(false);
                    textField.setBackground(UIManager.getColor("control"));
                    textField.select(0, 0);
                    textField.setBorder(BorderFactory.createEmptyBorder());
                    textField.setMargin(new Insets(0, 0, 0, 0));
                } else if (_component != null) {
                    _component.setEnabled(false);
                }
            } else {
                Border spacingBorder = BorderFactory.createEmptyBorder(
                                                                       VERT_COMPONENT_INSET, HORIZ_COMPONENT_INSET,
                                                                       VERT_COMPONENT_INSET, HORIZ_COMPONENT_INSET);
                Border loweredBorder =
                    new BevelBorder(BevelBorder.LOWERED,
                                    UIManager.getColor("controlHighlight"),
                                    UIManager.getColor("control"),
                                    UIManager.getColor("controlDkShadow"),
                                    UIManager.getColor("controlShadow"));
                if (_component instanceof JTextArea) {
                    JTextArea textArea = (JTextArea)_component;
                    textArea.setEditable(true);
                    textArea.setBackground(Color.white);
                    textArea.select(0, 0);
                    // valueLabel.setMargin(new Insets()); // doesn't work, using compound border instead...

                    textArea.setBorder( BorderFactory.createCompoundBorder(
                                                                           loweredBorder, spacingBorder));
                    _originalValue = textArea.getText();
				} else if ((_component instanceof JTextField) &&
						   !(_component instanceof JPasswordField)) {
                    JTextField textField = (JTextField)_component;
                    textField.setEditable(true);
                    textField.setBackground(Color.white);
                    textField.select(0, 0);
                    // valueLabel.setMargin(new Insets()); // doesn't work, using compound border instead...

                    textField.setBorder( BorderFactory.createCompoundBorder(
                                                                            loweredBorder, spacingBorder));
                    _originalValue = textField.getText();

                } else if (_component instanceof JCheckBox) {
                    JCheckBox checkbox = (JCheckBox)_component;
                    _originalValue = Boolean.valueOf(checkbox.isSelected());
                    _component.setEnabled(true);
                } else if (_component != null) {
                    _component.setEnabled(true);
                }
            }
            validate();
            repaint();
        }

        public Object getValue() {
            if (_component instanceof JTextArea) {
                JTextArea textArea = (JTextArea)_component;
                return textArea.getText();
            } else if ((_component instanceof JTextField) &&
					   !(_component instanceof JPasswordField)) {
                JTextField textField = (JTextField)_component;
                return textField.getText();
			} else {
                return _component;
            }
        }

        public void actionCancel() {
            if (_component instanceof JTextArea) {
                JTextArea textArea = (JTextArea)_component;
                textArea.setText((String)_originalValue);
            } else if ((_component instanceof JTextField) &&
					   !(_component instanceof JPasswordField)){
                JTextField textField = (JTextField)_component;
                textField.setText((String)_originalValue);
			} else if (_component instanceof JCheckBox) {
                JCheckBox checkbox = (JCheckBox)_component;
                checkbox.setSelected(
                                     ((Boolean)_originalValue).booleanValue());
            } else {
                // TODO: handle other types of components
            }
            setEditable(false);
        }

        public void actionOK() {
            setEditable(false);
        }

        public void actionEdit() {
            setEditable(true);
        }
    }

    class NodeDataChangeListener implements ChangeListener {
        public void stateChanged(ChangeEvent e) {
            NodeData d = (NodeData) e.getSource();
            Object valueComponent = _valueTable.get(d.getID());
			if (valueComponent != null){
				Object newValue = d.getValue();
                if (newValue instanceof String) {
					if (valueComponent instanceof JTextArea) {
						((JTextArea) valueComponent).setText(
                                                             (String) newValue);
					} else if ((valueComponent instanceof JTextField) &&
						       !(valueComponent instanceof JPasswordField)) {
                        ((JTextField) valueComponent).setText(
                                                              (String) newValue);
					}
				}
            }
        }
    }

    class ChangeKeyListener extends KeyAdapter {
        public void keyPressed(KeyEvent e) {
            if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                NodeDataPanel.this.validate();
                NodeDataPanel.this.repaint();
            }
        }
    }

    class OpenButtonActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            _nodeInfo.actionNodeDataChanged(new NodeData(ID_OPEN, null));
        }
    }

    /**
     * Called when HELP button is pressed
     * Default implementation calls Help.showContextHelp
     * with product and topic parameters specified in
     * setHelpTopic.
     *
     * @see #setHelpTopic
     */
    protected void helpInvoked()
	{
		if(helpProduct == null || helpTopic == null)
			throw new IllegalStateException("Help product or token not set.");
		else
			Help.showContextHelp(helpProduct, helpTopic);
    }

}
