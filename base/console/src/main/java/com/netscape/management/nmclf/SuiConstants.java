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

/**
 * A set of numerical constants that define the amount
 * of spacing between UI widgets.
 *
 * @author UE group
 */
public interface SuiConstants {

    /**
     * amount of space from component border to content
     */
    public static final int HORIZ_COMPONENT_INSET = 3;
    public static final int VERT_COMPONENT_INSET = 0;

    /**
     * amount of space between two components (buttons, etc.)
     * use horizontally or vertically
     */
    public static final int COMPONENT_SPACE = 6;

    /**
     * amount of space between two components (such as a group)
     * that need to be visually separated
     */
    public static final int SEPARATED_COMPONENT_SPACE = 12;

    /**
     * amount of space between two components that have different visual
     * effects - ie. a push button and an edit field (the push button
     * extends from the window, an edit field is grooved 'into' the window
     */
    public static final int DIFFERENT_COMPONENT_SPACE = 9;

    /**
     * insets from the top and edges of windows to components
     */
    public static final int HORIZ_WINDOW_INSET = 9;
    public static final int VERT_WINDOW_INSET = 9;

    /**
     * insets from the top and edges of dialogs to components
     */
    public static final int HORIZ_DIALOG_INSET = 18;
    public static final int VERT_DIALOG_INSET = 18;

    /**
     * button sizes must be a multiple of this (button_size modulus BUTTON_SIZE_MULTIPLE = 0)
     */
    public static final int BUTTON_SIZE_MULTIPLE = 18;

    /**
     * Font names to be used with UIManager.getFont("name").
     * These key names refer to various UI areas, not the actual font names.
     * These actual fonts returned will be those choosen by
     * the user's preferences.
     */
    public static String KEY_CONTROL_FONT = "CONTROLS";
    public static String KEY_DATA_FONT = "DATA_VARIABLE";
    public static String KEY_MONOSPACED_FONT = "DATA_FIXED";
    public static String KEY_STATUS_FONT = "STATUS";
    public static String KEY_TITLE_FONT = "TITLE";
    public static String KEY_TASK_FONT = "TASK";
}
