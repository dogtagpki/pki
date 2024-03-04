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
import javax.swing.plaf.*;
import javax.swing.tree.*;
import javax.swing.plaf.basic.*;

/**
 * A UI for JTree.  The original intent was to use curved lines
 * to connect tree nodes, but since this didn't work out,
 * we have reverted back to using dotted lines for windows and
 * solid lines for all other platforms.
 */
public class SuiTreeUI extends BasicTreeUI {
    static final int ROW_HEIGHT = 18; // theirs
    static final int ICON_SIZE = 7; // mine

    static Color hashColor;
    static Color hashLighterColor;


    public SuiTreeUI() {
        super();
    }

    public void installUI(JComponent c) {
        super.installUI(c);
        setRowHeight(ROW_HEIGHT);

        // TODO should these be moved into the defaults?
        //setExpandedIcon(SuiExpandedIcon.INSTANCE);
        //setCollapsedIcon(SuiCollapsedIcon.INSTANCE);

        //static final Icon LEAF_ICON = UIManager.getIcon("Tree.leafIcon");
        setExpandedIcon(UIManager.getIcon("Tree.expandedIcon"));
        setCollapsedIcon(UIManager.getIcon("Tree.collapsedIcon"));

        hashColor = UIManager.getColor("Tree.hash");
        hashLighterColor = UIManager.getColor("Tree.hashLighter");

        //		setLeftChildIndent(getLeftChildIndent() + 10);
        //		setRightChildIndent(getRightChildIndent() - 6);
    }

    protected void paintVerticalLine(Graphics g, JComponent c, int x,
            int top, int bottom) {
        if (SuiLookAndFeel._isWindows)
            drawDashedVerticalLine(g, x, top, bottom);
        else
            super.paintVerticalLine(g, c, x, top, bottom);
    }

    protected void paintHorizontalLine(Graphics g, JComponent c, int y,
            int left, int right) {
        if (SuiLookAndFeel._isWindows)
            drawDashedHorizontalLine(g, y, left, right);
        else
            super.paintHorizontalLine(g, c, y, left, right);
    }

    /* commented out because loopy legs don't draw with in large tree model
         // BasicTreeUI overrides
     	public void drawVerticalPartOfLeg( Graphics g, JComponent c,
     					  int depth, int parentY, int childY,
     					  int parentRowHeight, int childRowHeight )
     	{
     		int levelOffset = getShowsRootHandles() ? 1 : 0;
     		// the 8 must be half the parent icon width... cheating?
             int lineX = ((depth + levelOffset) * totalChildIndent) + 8;

     		Rectangle clipBounds = g.getClipBounds();
     		int clipLeft = clipBounds.x;
     		int clipRight = clipBounds.x + (clipBounds.width - 1);

     		if ( lineX > clipLeft && lineX < clipRight ) {
     	    	int clipTop = clipBounds.y;
     	    	int clipBottom = clipBounds.y + clipBounds.height;

     	    	int top = Math.max( parentY + parentRowHeight + getVerticalLegBuffer(), clipTop );
     	    	//int bottom = Math.min( childY + (childRowHeight / 2), clipBottom );
     	    	int bottom = Math.min(childY + 4, clipBottom);

     	    	g.setColor( getHashColor() );
     	    	//drawVerticalLine( g, c, lineX, top, bottom );
     	    	drawDashedVerticalLine(g, lineX, top, bottom);
     	  	}
     	}

         public void drawHorizontalPartOfLeg(Graphics g, JComponent c,
                                             int lineY, int leftX, int rightX)
         {
     		Rectangle clipBounds = g.getClipBounds();
     		int clipLeft = clipBounds.x;
     		int clipRight = clipBounds.x + (clipBounds.width - 1);
     		int clipTop = clipBounds.y;
     		int clipBottom = clipBounds.y + (clipBounds.height - 1);

     		rightX -= getHorizontalLegBuffer();

     		// if it goes to childX, it will go past the arrow icon
     		// it it goes short of the arrow icon, there will be a gap
     		// arrow icon is up to 7 pixels wide, so 3 is a good number
     		rightX -= 3;

     		if (lineY > clipTop && lineY < clipBottom &&
     		    rightX > clipLeft && leftX < clipRight) {
     	    	leftX = Math.max( leftX, clipLeft );
     	    	rightX = Math.min( rightX, clipRight );

     	    	//g.setColor(getHashColor());
     	    	g.setColor(hashColor);

         		// 5 over for the swing, 4 less for the arrow
     			int startX = leftX + 5;
     			drawDashedHorizontalLine(g, lineY, startX, rightX);

     			// the following need to be shifted to an odd pixel
     			// value, unlike drawDashedHorizontalLine, which draws on
     			// even pixels. the important thing is to first line up
     			// with the vertical.
     			if ((startX % 2) == 0) startX++;

     			// next draw the loopy part
     			g.drawLine(startX - 1, lineY - 1, startX - 1, lineY - 1);
     			g.drawLine(startX - 3, lineY - 2, startX - 3, lineY - 2);
     			g.drawLine(startX - 4, lineY - 4, startX - 4, lineY - 4);

     			// and the little cheat pixel
     			g.setColor(hashLighterColor);
     			g.drawLine(startX - 5, lineY - 4, startX - 5, lineY - 4);

     			// finally, restore to 'original' color (since it's assumed
     			// that this function doesn't set the color at all)
     			g.setColor(hashColor);

     	    	//drawHorizontalLine(g, c, lineY, leftX, rightX );
     		}
         }


         protected void drawDashedVerticalLine(Graphics g, int x, int y1, int y2)
         {
     		if ((y1 % 2) == 0) y1++;

     		for (int y = y1; y <= y2; y+=2) {
     		    g.drawLine(x, y, x, y);
     		}
         }

     	protected boolean clickedInExpandControl( VisibleTreeNode node, LargeTreeModelNode eNode,int row, int rowLevel, int mouseX, int mouseY )
     	{
     		if(rowLevel == 0)
     			return false;  // don't want top node to collapse

     		int boxWidth = totalChildIndent;
     		int boxLeftX;

     		if(this.getShowsRootHandles())
     			boxLeftX = ((rowLevel * totalChildIndent) + getLeftChildIndent());
     		else
     			boxLeftX = (((rowLevel - 1) * totalChildIndent) + getLeftChildIndent());

     		int boxRightX = boxLeftX + boxWidth;

     		return mouseX >= boxLeftX && mouseX <= boxRightX;
     	}
     */
    public static ComponentUI createUI(JComponent x) {
        return new SuiTreeUI();
    }

    public TreeCellRenderer getDefaultCellRenderer() {
        return new SuiTreeCellRenderer();
    }
}
