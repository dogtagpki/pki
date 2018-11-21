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
 * Copyright (C) 2018 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 *
 * @author Endi S. Dewata
 */

var ProfileModel = Model.extend({
    urlRoot: "/ca/rest/profiles",
    parseResponse: function(response) {
        return {
            id: response.id,
            classId: response.classId,
            name: response.name,
            description: response.description,
            enabled: response.enabled,
            visible: response.visible,
            enabledBy: response.enabledBy,
            authenticatorId: response.authenticatorId,
            authzAcl: response.authzAcl,
            renewal: response.renewal,
        };
    }
});

var ProfileCollection = Collection.extend({
    urlRoot: "/ca/rest/profiles",
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        return new ProfileModel({
            id: entry.profileId,
            name: entry.profileName,
            description: entry.profileDescription,
        });
    }
});

var ProfilePage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        ProfilePage.__super__.initialize.call(self, options);
    }
});

var ProfilesTable = ModelTable.extend({
    initialize: function(options) {
        var self = this;
        ProfilesTable.__super__.initialize.call(self, options);
    }
});

var ProfilesPage = Page.extend({
    load: function() {
        var self = this;

        var table = new ProfilesTable({
            el: $("table[name='profiles']"),
            collection: self.collection
        });

        table.render();
    }
});
