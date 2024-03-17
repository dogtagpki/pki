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

import java.awt.Font;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;

import javax.swing.UIManager;
import javax.swing.plaf.FontUIResource;

import com.netscape.management.client.util.ResourceSet;

public class FontFactory
{
    private static Hashtable fontHashtable = new Hashtable();

    public static final String FONT_CONTROL = "CONTROLS";
    public static final String FONT_DATA = "DATA_VARIABLE";
    public static final String FONT_MONOSPACED = "DATA_FIXED";
    public static final String FONT_STATUS = "STATUS";
    public static final String FONT_TITLE = "TITLE";
    public static final String FONT_TASK = "TASK";
    public static ResourceSet resource = new ResourceSet("com.netscape.management.client.components.components");

    static
    {
        fontHashtable.put(FONT_CONTROL, new FontUIResource("SansSerif", Font.PLAIN, 11));
        fontHashtable.put(FONT_DATA, new FontUIResource("SansSerif", Font.PLAIN, 11));
        fontHashtable.put(FONT_MONOSPACED, new FontUIResource("Monospaced", Font.PLAIN, 11));
        fontHashtable.put(FONT_STATUS, new FontUIResource("SansSerif", Font.PLAIN, 11));
        fontHashtable.put(FONT_TITLE, new FontUIResource("SansSerif", Font.PLAIN, 18));
        fontHashtable.put(FONT_TASK, new FontUIResource("SansSerif", Font.PLAIN, 18));
    }

    /**
      * Return localized string from the framework resource bundle
      */
    public static String i18n(String group, String id) {
        return resource.getString(group, id);
    }


    public static Enumeration getFontIDs()
    {
        return fontHashtable.keys();
    }

    /**
     * @param fontItemID a FONT constant (defined above)
     * @return font associated with this screen element
     */
    public static Font getFont(String fontID)
    {
        return (Font)fontHashtable.get(fontID);
    }

    /**
     * @param fontItemID a FONT constant (defined above)
     * @param f the font to associate with this screen element
     */
    public static void setFont(String fontID, Font f)
    {
        fontHashtable.put(fontID, f);
    }

    public static String getFontDescription(String fontID)
    {
        return i18n("font", fontID);
    }

    public static void initializeLFFonts()
    {
        Font fontControl = getFont(FONT_CONTROL);
        Font fontData = getFont(FONT_DATA);
        Font fontMono = getFont(FONT_MONOSPACED);
        Font fontStatus = getFont(FONT_STATUS);
        Font fontTitle = getFont(FONT_TITLE);
        Font fontTaskList = getFont(FONT_TASK);

        // Console specific fonts
        UIManager.put("TaskList.font", fontTaskList);
        UIManager.put("Title.font", fontTitle);
        UIManager.put("Status.font", fontStatus);

        UIManager.put("Button.font", fontControl);
        UIManager.put("ToggleButton.font", fontControl);
        UIManager.put("RadioButton.font", fontControl);
        UIManager.put("CheckBox.font", fontControl);
        UIManager.put("ColorChooser.font", fontControl);
        UIManager.put("ComboBox.font", fontControl);
        UIManager.put("Label.font", fontControl);
        UIManager.put("List.font", fontControl);
        UIManager.put("MenuBar.font", fontControl);
        UIManager.put("MenuItem.font", fontControl);
        UIManager.put("RadioButtonMenuItem.font", fontControl);
        UIManager.put("CheckBoxMenuItem.font", fontControl);
        UIManager.put("Menu.font", fontControl);
        UIManager.put("PopupMenu.font", fontControl);
        UIManager.put("OptionPane.font", fontControl);
        UIManager.put("Panel.font", fontControl);
        UIManager.put("ProgressBar.font", fontControl);
        UIManager.put("ScrollPane.font", fontControl);
        UIManager.put("Viewport.font", fontControl);
        UIManager.put("TabbedPane.font", fontControl);
        UIManager.put("Table.font", fontControl);
        UIManager.put("TableHeader.font", fontControl);
        UIManager.put("TextField.font", fontData);
        UIManager.put("PasswordField.font", fontMono);
        UIManager.put("TextArea.font", fontData);
        UIManager.put("TextPane.font", fontData);
        UIManager.put("EditorPane.font", fontData);
        UIManager.put("TitledBorder.font", fontControl);
        UIManager.put("ToolBar.font", fontControl);
        UIManager.put("ToolTip.font", fontData);
        UIManager.put("Tree.font", fontData);
    }

    public static String toFontInfoString(Font f) {
        return f.getName() + ":" + String.valueOf(f.getStyle()) + ":" +
                String.valueOf(f.getSize());
    }

    public static Font toFont(String fontInfo) {
        String name = "SansSerif";
        int style = Font.PLAIN;
        int size = 11;

        StringTokenizer st = new StringTokenizer(fontInfo, ":");
        if (st.hasMoreTokens()) {
            name = st.nextToken();
            Integer i = Integer.valueOf(st.nextToken());
            style = i.intValue();
            i = Integer.valueOf(st.nextToken());
            size = i.intValue();
        }
        return new Font(name, style, size);
    }
}
