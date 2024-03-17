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

package com.netscape.management.client.util;

/**
 * A two-way linked list.
 * Used internally by Console.
 */
public class LinkedList {
    public LinkedListElement head;
    public LinkedListElement tail;
    public int size;

    public LinkedList() {
        head = null;
        tail = null;
        size = 0;
    }

    public void prepend(Object obj) {
        LinkedListElement e = new LinkedListElement(obj);

        if (size == 0) {
            head = tail = e;
            size++;
            return;
        }

        e.next = head;
        head.prev = e;
        head = e;
        size++;
    }

    public void append(Object obj) {
        LinkedListElement e = new LinkedListElement(obj);

        if (size == 0) {
            head = tail = e;
            size++;
            return;
        }

        e.prev = tail;
        tail.next = e;
        tail = e;
        size++;
    }

    public void insertAfter(Object obj, Object after) {
        LinkedListElement p = head;

        while (p != null) {
            if (p.obj != after) {
                p = p.next;
                continue;
            }

            LinkedListElement e = new LinkedListElement(obj);

            if (p.next == null) {
                p.next = e;
                e.prev = p;
                tail = e;
                size++;
                return;
            }

            p.next.prev = e;
            e.next = p.next;
            p.next = e;
            e.prev = p;
            size++;
            return;
        }

        append(obj);
    }

    public void insertBefore(Object obj, Object before) {
        LinkedListElement p = head;

        while (p != null) {
            if (p.obj != before) {
                p = p.next;
                continue;
            }

            LinkedListElement e = new LinkedListElement(obj);

            if (p.prev == null) {
                p.prev = e;
                e.next = p;
                head = e;
                size++;
                return;
            }

            p.prev.next = e;
            e.next = p;
            e.prev = p.prev;
            p.prev = e;
            size++;
            return;
        }

        append(obj);
    }

    public boolean remove(Object obj) {
        LinkedListElement p = head;

        while (p != null) {
            if (p.obj != obj) {
                p = p.next;
                continue;
            }

            if (p.prev == null)
                head = p.next;
            else
                p.prev.next = p.next;

            if (p.next == null)
                tail = p.prev;
            else
                p.next.prev = p.prev;

            p.obj = null;
            p.prev = p.next = null;

            size--;

            return (true);
        }

        return (false);
    }

    public void removeAll() {
        LinkedListElement p = head;

        while (p != null) {
            LinkedListElement next = p.next;

            p.obj = null;
            p.prev = p.next = null;

            p = next;
        }

        head = tail = null;
        size = 0;
    }

    public String toString() {
        LinkedListElement p = head;
        String s = "List(size = " + size + "):\n";

        while (p != null) {
            s += "(Element: " + p.obj + ")\n";
            p = p.next;
        }

        return (s);
    }
}
