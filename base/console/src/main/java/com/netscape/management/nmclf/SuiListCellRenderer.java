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

import java.awt.*;
import javax.swing.*;
import javax.swing.border.*;

/**
 * 
 * @author Andy Hakim
 */
public class SuiListCellRenderer extends DefaultListCellRenderer 
{
	public SuiListCellRenderer() 
	{
        super();
		noFocusBorder = new EmptyBorder(0, 3, 0, 3);
		setBorder(noFocusBorder);
    }

	public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean hasFocus) 
	{
		super.getListCellRendererComponent(list, value, index, isSelected, hasFocus);
        return this;
    }
	
    /**
     * A subclass of DefaultListCellRenderer that implements UIResource.
     * DefaultListCellRenderer doesn't implement UIResource
     * directly so that applications can safely override the
     * cellRenderer property with DefaultListCellRenderer subclasses.
     * <p>
     * <strong>Warning:</strong>
     * Serialized objects of this class will not be compatible with
     * future Swing releases.  The current serialization support is appropriate
     * for short term storage or RMI between applications running the same
     * version of Swing.  A future release of Swing will provide support for
     * long term persistence.
     */
    public static class UIResource extends SuiListCellRenderer
        implements javax.swing.plaf.UIResource
    {
    }

}
