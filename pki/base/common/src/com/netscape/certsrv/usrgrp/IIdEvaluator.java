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
package com.netscape.certsrv.usrgrp;


import java.util.*;
import java.security.*;
import com.netscape.certsrv.base.*;


/**
 * A class represents an ID evaluator.
 * <P>
 * 
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface IIdEvaluator {

    /**
     * Evaluates if the given value satisfies the ID evaluation:
     * is a user a member of a group
     * @param type the type of evaluator, in this case, it is group
     * @param id the user id for the given user
     * @param op operator, only "=" and "!=" are supported
     * @param value the name of the group, eg, "Certificate Manager Agents"
     * @return true if the given user is a member of the group
     */
    public boolean evaluate(String type, IUser id, String op, String value);
}
