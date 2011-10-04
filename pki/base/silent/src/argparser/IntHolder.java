// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

/**
  * Wrapper class which ``holds'' an integer value,
  * enabling methods to return integer values through
  * arguments.
  */
public class IntHolder implements java.io.Serializable
{
	/**
	 * Value of the integer, set and examined
	 * by the application as needed.
	 */
	public int value;

	/**
	 * Constructs a new <code>IntHolder</code> with an initial
	 * value of 0.
	 */
	public IntHolder ()
	 { value = 0;
	 }

	/**
	 * Constructs a new <code>IntHolder</code> with a
	 * specific initial value.
	 *
	 * @param i Initial integer value.
	 */
	public IntHolder (int i)
	 { value = i;
	 }
}

