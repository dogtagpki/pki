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
package com.netscape.certsrv.evaluators;

import org.dogtagpki.server.authentication.AuthToken;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * A class represents an evaluator. An evaluator is used to
 * evaluate an expression. For example, one can write an evaluator to
 * evaluate if a user belongs to a certain group. An evaluator is
 * generally used for access control expression evaluation, however, it
 * can be used for other evaluation-related operations.
 */
public abstract class AccessEvaluator {

    protected CMSEngine engine;
    protected String type;
    protected String description;

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    /**
     * Initialize the evaluator
     */
    public abstract void init();

    /**
     * Gets the type of the evaluator. Type is defined by each
     * evaluator plugin. Each evaluator plugin should have a unique type.
     *
     * @return type of the evaluator
     */
    public String getType() {
        return type;
    }

    /**
     * Gets the description of the evaluator
     *
     * @return a text description for this evaluator
     */
    public String getDescription() {
        return description;
    }

    /**
     * Evaluates if the given value satisfies the access
     * control in current context.
     *
     * @param type Type of the evaluator, eg, user, group etc
     * @param op Operator of the evaluator, eg, =, !=
     * @param value Part of the expression that can be used to
     *            evaluate, e.g, value can be the name of the group if the
     *            purpose of the evaluator is to evaluate if the user is a member
     *            of the group.
     * @return true if the evaluation expression is matched; false otherwise.
     */
    public abstract boolean evaluate(String type, String op, String value);

    /**
     * Evaluates if the given value satisfies the access
     * control in authToken obtained from Authentication.
     *
     * @param authToken Authentication token
     * @param type Type of the evaluator, eg, user, group etc
     * @param op Operator of the evaluator, eg, =, !=
     * @param value Part of the expression that can be used to
     *            evaluate, e.g, value can be the name of the group if the
     *            purpose of the evaluator is to evaluate if the user is a member
     *            of the group.
     * @return true if the evaluation expression is matched; false otherwise.
     */
    public abstract boolean evaluate(AuthToken authToken, String type, String op, String value);

    /**
     * Get the supported operators for this evaluator
     *
     * @return Supported operators in string array
     */
    public abstract String[] getSupportedOperators();
}
