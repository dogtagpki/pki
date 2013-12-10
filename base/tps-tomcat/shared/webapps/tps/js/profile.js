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

var ProfileModel = Model.extend({
    urlRoot: "/tps/rest/profiles",
    parseResponse: function(response) {
        return {
            id: response.Profile["@id"],
            status: response.Profile.Status
        };
    },
    createRequest: function(attributes) {
        return {
            Profile: {
                "@id": attributes.id,
                Status: attributes.status
            }
        };
    }
});

var ProfileCollection = Collection.extend({
    urlRoot: "/tps/rest/profiles",
    getEntries: function(response) {
        return response.Profiles.Profile;
    },
    getLinks: function(response) {
        return response.Profiles.Link;
    },
    parseEntry: function(entry) {
        return new ProfileModel({
            id: entry["@id"],
            status: entry.Status
        });
    }
});

var ProfileDialog = Dialog.extend({
    performAction: function(action) {
        var self = this;

        if (action == "enable") {

        } else if (action == "disable") {

        } else {
            ProfileDialog.__super__.performAction.call(self, action);
        }
    }
});
