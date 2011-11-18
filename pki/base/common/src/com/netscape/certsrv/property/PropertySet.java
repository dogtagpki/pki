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
package com.netscape.certsrv.property;

import java.util.Enumeration;
import java.util.Hashtable;


/**
 * A set of properties.
 */
public class PropertySet {

  private Hashtable<String, IDescriptor> mProperties = new Hashtable<String, IDescriptor>();

  public PropertySet()
  {
  }

  public void add(String name, IDescriptor desc)
  {
     mProperties.put(name, desc);
  }

  public Enumeration<String> getNames()
  {
    return mProperties.keys();
  }

  public IDescriptor getDescriptor(String name)
  {
    return (IDescriptor)mProperties.get(name);
  }

  public void remove(String name)
  {
    mProperties.remove(name);
  }

  public int size()
  {
    return mProperties.size();
  }
}
