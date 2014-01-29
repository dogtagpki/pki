/* --- BEGIN COPYRIGHT BLOCK ---
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 *
 * @author Endi S. Dewata
 */

var SelfTestModel = Model.extend({
    urlRoot: "/tps/rest/selftests",
    parseResponse: function(response) {
        return {
            id: response.id,
            enabledAtStartup: response.EnabledAtStartup,
            criticalAtStartup: response.CriticalAtStartup,
            enabledOnDemand: response.EnabledOnDemand,
            criticalOnDemand: response.CriticalOnDemand,
        };
    },
    createRequest: function(attributes) {
        return {
            id: attributes.id,
            EnabledAtStartup: attributes.enabledAtStartup,
            CriticalAtStartup: attributes.criticalAtStartup,
            EnabledOnDemand: attributes.enabledOnDemand,
            CriticalOnDemand: attributes.criticalOnDemand
        };
    }
});

var SelfTestCollection = Collection.extend({
    urlRoot: "/tps/rest/selftests",
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        return new SelfTestModel({
            id: entry.id,
            enabledAtStartup: entry.EnabledAtStartup,
            criticalAtStartup: entry.CriticalAtStartup,
            enabledOnDemand: entry.EnabledOnDemand,
            criticalOnDemand: entry.CriticalOnDemand,
        });
    }
});
