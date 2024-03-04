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
package com.netscape.management.nmclf;

import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Insets;
import java.awt.SystemColor;
import java.io.Serializable;

import javax.swing.BorderFactory;
import javax.swing.LookAndFeel;
import javax.swing.UIDefaults;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.plaf.BorderUIResource;
import javax.swing.plaf.ColorUIResource;
import javax.swing.plaf.InsetsUIResource;
import javax.swing.plaf.basic.BasicBorders;
import javax.swing.plaf.basic.BasicGraphicsUtils;
import javax.swing.plaf.metal.MetalLookAndFeel;

import com.netscape.management.client.util.RemoteImage;

/**
 * This Look and Feel class customizes certain JFC widgets.
 * Some customizations are done to provide a Netscape identity,
 * while other changes fix JFC visual and functional bugs.
 *
 * This package has undergone a major overhaul in Console 5.0.
 * A lot of dead-code was removed, and most dependencies to
 * console packages were removed.
 *
 * @author Ben fry
 * @author Andy Hakim
 */
public class SuiLookAndFeel extends MetalLookAndFeel implements Serializable, SuiConstants
{
    public static final boolean _isWindows =
            System.getProperty("os.name").startsWith("Windows");

    public String getName()
    {
        return "Console Look and Feel";
    }

    public String getID()
    {
        return "NMCLF";
    }

    public String getDescription()
    {
        return "";
    }

    public boolean isNativeLookAndFeel()
    {
        return _isWindows;
    }

    public boolean isSupportedLookAndFeel()
    {
        return true;
    }

    /**
     * Override the parent initialize method.
     *
     * With JDK1.4, the parent Win L&F will fail to initialize if
     * the OS version contains letters (e.g. B.11.11 for hpux).
     * Adjust the version string, if necessary, and restore the
     * original one afterwards.
     */
    public void initialize() {

        String osVersion = System.getProperty("os.version");
        String osVersionTemp = null;

        try {
            try {
                Float.parseFloat(osVersion);
            }
            catch (NumberFormatException e) {
                // Set a fake os version number
                osVersionTemp = "4.0";
                System.setProperty("os.version", osVersionTemp);
            }

            super.initialize();
        }
        finally {
            // Restore the real os version
            if (osVersionTemp != null) {
                System.setProperty("os.version", osVersion);
            }
        }
    }

    public UIDefaults getDefaults()
    {
        UIDefaults table = new UIDefaults();
        initClassDefaults(table);
        initSystemColorDefaults(table);
        initComponentDefaults(table);
        return table;
    }

    /**
      * Initialize the uiClassID to BasicComponentUI mapping.
      * The JComponent classes define their own uiClassID constants
      * (see AbstractComponent.getUIClassID).  This table must
      * map those constants to a BasicComponentUI class of the
      * appropriate type.
      *
      * @see #getDefaults
      */
    protected void initClassDefaults(UIDefaults table) {
        super.initClassDefaults(table);

        String suiPackageName = "com.netscape.management.nmclf.";

        Object[] uiDefaults =
        {
            "TreeUI", suiPackageName + "SuiTreeUI",
            "TableUI", suiPackageName + "SuiTableUI",
            "ComboBoxUI", suiPackageName + "SuiComboBoxUI",
            "OptionPaneUI", suiPackageName + "SuiOptionPaneUI"
        };

        table.putDefaults(uiDefaults);
    }

    /**
     * If this is the native look and feel the initial values for the
     * system color properties are the same as the SystemColor constants.
     * If not we use the integer color values in the <code>systemColors</code>
     * argument.
     */
    protected void loadSystemColors(UIDefaults table, String[] systemColors, boolean useNative)
    {
        if (useNative) {
            for(int i = 0; i < systemColors.length; i += 2) {
                Color color = Color.black;
                try {
                    String name = systemColors[i];
                    color = (Color)(SystemColor.class.getField(name).get(null));
                } catch (Exception e) {
                }
                table.put(systemColors[i], new ColorUIResource(color));
            }
            // ahakim: now tweak the standard colors a little bit
            table.put("scrollbar", new ColorUIResource(Color.decode("#E0E0E0")));  // Scrollbar background (usually the "track")
        } else {
            /* PENDING(hmuller) We don't load the system colors below because
             * they're not reliable.  Hopefully we'll be able to do better in
             * a future version of AWT.
             */
            for(int i = 0; i < systemColors.length; i += 2) {
                Color color = Color.black;
                try {
                    color = Color.decode(systemColors[i + 1]);
                }
                catch(NumberFormatException e) {
                    e.printStackTrace();
                }
                table.put(systemColors[i], new ColorUIResource(color));
            }
        }
    }

    protected void initComponentDefaults(UIDefaults table)
    {
        super.initComponentDefaults(table);

        SuiFieldBorder fb = new SuiFieldBorder((Color)table.get("controlShadow"),
                                               (Color)table.get("controlDkShadow"),
                                               (Color)table.get("controlHighlight"),
                                               (Color)table.get("controlLtHighlight"));

        Object textBorder = new UIDefaults.LazyValue() {
            public Object createValue(UIDefaults table)
            {
                return new BorderUIResource( new CompoundBorder(
                        SuiFieldBorder.getFieldBorder(),
                        new BasicBorders.MarginBorder()));
            }
        };

        Object buttonBorder = new UIDefaults.LazyValue()
        {
                public Object createValue(UIDefaults table)
                {
                    return new BorderUIResource.CompoundBorderUIResource(
                            new BasicBorders.ButtonBorder(
                                           table.getColor("controlShadow"),
                                           table.getColor("controlDkShadow"),
                                           table.getColor("control"),
                                           table.getColor("controlLtHighlight")),
                            new BasicBorders.MarginBorder());
                }
        };

        // default selection/highlight color
        ColorUIResource highlightColor = new ColorUIResource(204, 204, 255);

        // default 'tainted data' (unsaved changes) color, for the righthand pane
        ColorUIResource modifiedColor = new ColorUIResource(102, 102, 153);
        ColorUIResource errorColor = new ColorUIResource(204, 0, 0);

        Border focusCellHighlightBorder = BorderFactory.createEmptyBorder(0, 3, 0, 3);

        Object listCellRendererActiveValue = new UIDefaults.ActiveValue()
        {
            public Object createValue(UIDefaults table)
            {
                return new SuiListCellRenderer();
            }
        };

        // Only add stuff to default array that replaces WindowsLookAndFeel/BasicLookAndFeel
        Object[] defaults =
        {
            "List.focusCellHighlightBorder", focusCellHighlightBorder,
            "List.cellRenderer", listCellRendererActiveValue,
            "List.nonSelectionBackground", table.get("controlText"),

            "TabbedPane.contentBorderInsets", new InsetsUIResource(1, 1, 2, 2),

            "Tree.leftChildIndent", Integer.valueOf(7),
            "Tree.rightChildIndent", Integer.valueOf(13),
            "Tree.rowHeight", Integer.valueOf(18),
            "Tree.scrollsOnExpand", Boolean.TRUE,
            "Tree.openIcon", LookAndFeel.makeIcon(getClass(), "icons/TreeOpen.gif"),
            "Tree.closedIcon", LookAndFeel.makeIcon(getClass(), "icons/TreeClosed.gif"),
            "Tree.leafIcon", LookAndFeel.makeIcon(getClass(), "icons/TreeLeaf.gif"),
            "Tree.expandedIcon", null,
            "Tree.collapsedIcon", null,
            "Tree.changeSelectionWithFocus", Boolean.TRUE,
            "Tree.drawsFocusBorderAroundIcon", Boolean.FALSE,

            "TabbedPane.tabInsets", new InsetsUIResource(0, 15, 1, 15),

            "Label.error", errorColor,         // TODO: possibly never used, remove
            "Label.modified", modifiedColor,   // TODO: possibly never used, remove

            "SplitPane.dividerSize", Integer.valueOf(4),

            "ComboBox.border", textBorder,
            "ComboBox.background", table.get("window"),
            "ComboBox.foreground", Color.black,

            "Table.focusCellHighlightBorder", focusCellHighlightBorder,
            "Table.scrollPaneBorder", textBorder,
            "PasswordField.border", textBorder,
            "TextField.border", textBorder,
            "Button.border", buttonBorder,
            "ScrollPane.border", textBorder,

            "TextField.margin", new InsetsUIResource(0, 3, 0, 3),
            "TextArea.margin", new InsetsUIResource(0, 3, 0, 3),
            "Button.margin", new InsetsUIResource(0, 15, 0, 15),

            "Tree.background", table.get("window"),
            "Tree.textSelectionColor", table.get("textSelectionColor"),
            "Tree.textNonSelectionColor", table.get("controlText"),
            "Tree.collapsedIcon", LookAndFeel.makeIcon(getClass(), "icons/TreeExpander.gif"),
            "Tree.expandedIcon", LookAndFeel.makeIcon(getClass(), "icons/TreeCollapser.gif"),

            "OptionPane.errorIcon", new RemoteImage("com/netscape/management/nmclf/icons/Error.gif"),
            "OptionPane.informationIcon", new RemoteImage("com/netscape/management/nmclf/icons/Inform.gif"),
            "OptionPane.warningIcon", new RemoteImage("com/netscape/management/nmclf/icons/Warn.gif"),
            "OptionPane.questionIcon", new RemoteImage("com/netscape/management/nmclf/icons/Question.gif"),
        };
        table.putDefaults(defaults);
    }
}


// needed to fix hard-coded color value in BasicGraphicsUtils
class SuiGraphicsUtils extends BasicGraphicsUtils {
    public static void drawEtchedRect(Graphics g, int x, int y, int w,
            int h, Color shadow, Color darkShadow, Color highlight, Color lightHighlight) {
        Color oldColor = g.getColor(); // Make no net change to g
        g.translate(x, y);

        g.setColor(shadow);
        g.drawLine(0, 0, w - 1, 0); // outer border, top
        g.drawLine(0, 1, 0, h - 2); // outer border, left

        g.setColor(darkShadow);
        g.drawLine(1, 1, w - 3, 1); // inner border, top
        g.drawLine(1, 2, 1, h - 3); // inner border, left

        g.setColor(highlight);
        g.drawLine(w - 2, 1, w - 2, h - 3); // inner border, right
        g.drawLine(1, h - 2, w - 3, h - 2); // inner border, bottom

        g.setColor(lightHighlight);
        g.drawLine(0, h - 1, w - 1, h - 1); // outer border, right
        g.drawLine(w - 1, 0, w - 1, h - 1); // outer border, bottom

        g.translate(-x, -y);
        g.setColor(oldColor);
    }
}


// needed to create proper border for various components
class SuiFieldBorder extends BasicBorders.FieldBorder {
    private static Border fieldBorder = null;

    public SuiFieldBorder(Color shadow, Color darkShadow, Color highlight, Color lightHighlight)
    {
        super(shadow, darkShadow, highlight, lightHighlight);

        if (fieldBorder == null)
        {
            fieldBorder = this;
        }
    }

    public static Border getFieldBorder() {
        return fieldBorder;
    }

    public void paintBorder(Component c, Graphics g, int x, int y,
            int width, int height) {
        SuiGraphicsUtils.drawEtchedRect(g, x, y, width, height, shadow, darkShadow, highlight, lightHighlight);
    }

    public Insets getBorderInsets(Component c) {
        return new Insets(2, 2, 2, 2);
    }
}
