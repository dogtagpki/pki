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
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.ConsoleHelp;

/**
 * A dialog that allows fonts to be choosen.
 * 
 * @author Andy Hakim
 * @author Thu Le
 */
public class FontChooserDialog extends GenericDialog 
{
    private static int fontSizes[] = { 8, 10, 11, 12, 16, 18, 24, 28 };
    private JTextField fontField;
    private JTextField sizeField;
    private String fontArray[];
    private String sizeArray[];
    private JList fontList;
    private JList sizeList;
    private JCheckBox boldCheckbox;
    private JCheckBox italicCheckbox;
    private JLabel sampleLabel = new JLabel();
    private String selectedName;
    private int selectedSize;
    private int fontStyle;
    private static ResourceSet resource = new ResourceSet("com.netscape.management.client.components.components");

    static String i18n(String id) 
    {
        return resource.getString("fontChooser", id);
    }

    public FontChooserDialog(JFrame parentFrame, String initialName, int initialStyle, int initialSize) 
    {
        super(parentFrame, i18n("select"), OK | CANCEL | HELP);
        Vector sizeVector = new Vector();
        for (int i = 0; i < fontSizes.length; i++) {
            sizeVector.addElement(String.valueOf(fontSizes[i]));
        }

        sizeArray = new String[sizeVector.size()];
        sizeVector.copyInto(sizeArray);
        sizeList = new JList(sizeArray);
        sizeList.setToolTipText(i18n("size_tt"));
        sizeList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        Toolkit t = Toolkit.getDefaultToolkit();
        fontArray = t.getFontList();
        GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
        fontArray = ge.getAvailableFontFamilyNames();        
        fontList = new JList(fontArray);
        fontList.setToolTipText(i18n("font_tt"));
        fontList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        getContentPane().add(createDialogPanel());
        sizeField.setText(String.valueOf(initialSize));
        fontField.setText(initialName);
        boldCheckbox.setSelected((initialStyle & Font.BOLD) == Font.BOLD);
        italicCheckbox.setSelected((initialStyle & Font.ITALIC) == Font.ITALIC);
        
        updateFontList();
        updateSizeList();
        
        EventListener l = new ChangeEventListener();
        fontField.getDocument().addDocumentListener((DocumentListener) l);
        sizeField.getDocument().addDocumentListener((DocumentListener) l);
        fontList.addListSelectionListener((ListSelectionListener) l);
        sizeList.addListSelectionListener((ListSelectionListener) l);
        italicCheckbox.addChangeListener((ChangeListener) l);
        boldCheckbox.addChangeListener((ChangeListener) l);
    }

    public String getFontName() {
        return selectedName;
    }

    public int getFontSize() {
        return selectedSize;
    }

    public int getFontStyle() {
        return fontStyle;
    }

    protected void okInvoked() {
        selectedName = (String)fontList.getSelectedValue();
        String sizeString = (String)sizeField.getText();
        if(sizeString == "")
            sizeString = "11";
        Integer sizeInteger = Integer.valueOf(sizeString);
        selectedSize = sizeInteger.intValue();
        fontStyle = Font.PLAIN;
        fontStyle += (italicCheckbox.isSelected() ? Font.ITALIC : 0);
        fontStyle += (boldCheckbox.isSelected() ? Font.BOLD : 0);
        super.okInvoked();
    }

    protected JPanel createDialogPanel() {
        JPanel panel = new JPanel();
        GridBagLayout gridbag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();

        panel.setLayout(gridbag);

        JLabel fontLabel = new JLabel(UITools.getDisplayLabel(i18n("font")));
		fontField = new JTextField(12);
        fontLabel.setLabelFor(fontField);
		
        GridBagUtil.constrain(panel, fontLabel, 0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.NONE,
                0, 0, 0, SEPARATED_COMPONENT_SPACE);
        
        GridBagUtil.constrain(panel, fontField, 0, 1, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 1, SEPARATED_COMPONENT_SPACE);

        JScrollPane fontPane = new JScrollPane(fontList);
        GridBagUtil.constrain(panel, fontPane, 0, 2, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                0, 0, 0, SEPARATED_COMPONENT_SPACE);

        JLabel sizeLabel = new JLabel(UITools.getDisplayLabel(i18n("size")));
		sizeField = new JTextField(3);
		sizeLabel.setLabelFor(sizeField);

        GridBagUtil.constrain(panel, sizeLabel, 1, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.NONE,
                0, 0, 0, 0);
        
        GridBagUtil.constrain(panel, sizeField, 1, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.NONE,
                0, 0, 1, 0);

        JScrollPane sizePane = new JScrollPane(sizeList);
        GridBagUtil.constrain(panel, sizePane, 1, 2, 1, 1, 0.0, 1.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.VERTICAL,
                0, 0, 0, 0);

        Border b = BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(null, i18n("sample")),
                BorderFactory.createEmptyBorder(2, 6, 6, 4));
        sampleLabel.setBorder(b);
        sampleLabel.setText(i18n("sampleText"));
        sampleLabel.setToolTipText(i18n("sample_tt"));
        sampleLabel.setMaximumSize(new Dimension(100, 50));
        sampleLabel.setPreferredSize(new Dimension(100, 50));
        GridBagUtil.constrain(panel, sampleLabel, 0, 3, 2, 1, 0.0, 0.0, 
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                COMPONENT_SPACE, 0, 0, 0);

        JPanel checkPanel = new JPanel(new GridBagLayout());
        boldCheckbox = new JCheckBox(UITools.getDisplayLabel(i18n("bold")));
        italicCheckbox = new JCheckBox(UITools.getDisplayLabel(i18n("italic")));
        
        GridBagUtil.constrain(checkPanel,
                boldCheckbox, 0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.NONE,
                SEPARATED_COMPONENT_SPACE * 2, 0, 0, 0);
        
        GridBagUtil.constrain(checkPanel,
                italicCheckbox, 0, 1, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.NONE,
                0, 0, 0, 0);
        
        setButtonComponent(checkPanel);
        return panel;
    }
	
	private void setRegisterKeyboardAction(char c, JComponent component, ActionListener l)
	{
		char upperChar = Character.toUpperCase(c);
		char lowerChar = Character.toLowerCase(c);
		component.registerKeyboardAction(l,
			KeyStroke.getKeyStroke(Character.getNumericValue(upperChar),KeyEvent.VK_ALT),
            JComponent.WHEN_IN_FOCUSED_WINDOW);
		component.registerKeyboardAction(l,
			KeyStroke.getKeyStroke(Character.getNumericValue(lowerChar),KeyEvent.VK_ALT),
            JComponent.WHEN_IN_FOCUSED_WINDOW);
	}
	
    public void updateFontList() {
        String s = fontField.getText();
        int bestMatch = -1;
        if(s.length() > 0)
        {
            for (int i = fontArray.length - 1; i >= 0 ; i--) {
                String s1 = s.toLowerCase();
                String s2 = fontArray[i].toLowerCase();
                if (s2.startsWith(s1))
                    bestMatch = i;
            }
        }
        if(bestMatch != -1)
        {
            fontList.setSelectedIndex(bestMatch);
            fontList.ensureIndexIsVisible(bestMatch);
            updateFontSample();
        }
        else
        {
            ListSelectionModel lsm = fontList.getSelectionModel();
            lsm.clearSelection();
        }
    }

    public void updateSizeList() {
        String s = sizeField.getText();
        String bestMatch = "";
        for (int i = sizeArray.length - 1; i >= 0 ; i--) {
            String s1 = s;
            String s2 = sizeArray[i];
            if (s2.equals(s1))
                bestMatch = s2;
        }
        sizeList.setSelectedValue(bestMatch, true);
    }

    void updateFontSample() {
        String name = (String)fontList.getSelectedValue();
        String sizeString = (String)sizeList.getSelectedValue();
        if(sizeString == null)
            sizeString = "11";
        Integer sizeInteger = Integer.valueOf(sizeString);
        int style = Font.PLAIN;
        style += (italicCheckbox.isSelected() ? Font.ITALIC : 0);
        style += (boldCheckbox.isSelected() ? Font.BOLD : 0);
        sampleLabel.setFont(new Font(name, style, sizeInteger.intValue()));
    }

    class ChangeEventListener implements ListSelectionListener,
    ChangeListener, DocumentListener {
        int oldFontListSelection = -1;
        int oldSizeListSelection = -1;

        public void valueChanged(ListSelectionEvent e) {
            if (oldFontListSelection != fontList.getSelectedIndex()) {
                updateFontSample();
                fontField.getDocument().removeDocumentListener(this);
                fontField.setText((String)fontList.getSelectedValue());
                fontField.getDocument().addDocumentListener(this);
                oldFontListSelection = fontList.getSelectedIndex();
            }

            if (oldSizeListSelection != sizeList.getSelectedIndex()) {
                updateFontSample();
                sizeField.getDocument().removeDocumentListener(this);
                sizeField.setText((String)sizeList.getSelectedValue());
                sizeField.getDocument().addDocumentListener(this);
                oldSizeListSelection = sizeList.getSelectedIndex();
            }
        }

        public void stateChanged(ChangeEvent e) {
            updateFontSample();
        }

        public void insertUpdate(DocumentEvent e) {
            fontList.removeListSelectionListener(this);
            sizeList.removeListSelectionListener(this);
            updateFontList();
            updateSizeList();
            fontList.addListSelectionListener(this);
            sizeList.addListSelectionListener(this);
        }

        public void removeUpdate(DocumentEvent e) {
            fontList.removeListSelectionListener(this);
            sizeList.removeListSelectionListener(this);
            updateFontList();
            updateSizeList();
            fontList.addListSelectionListener(this);
            sizeList.addListSelectionListener(this);
        }

        public void changedUpdate(DocumentEvent e) {
            fontList.removeListSelectionListener(this);
            sizeList.removeListSelectionListener(this);
            updateFontList();
            updateSizeList();
            fontList.addListSelectionListener(this);
            sizeList.addListSelectionListener(this);
        }
    }

	/**
	 * Called when the Help button is pressed.
	 */
    public void helpInvoked()
	{
		ConsoleHelp.showContextHelp("fontChooser");
	}
}
