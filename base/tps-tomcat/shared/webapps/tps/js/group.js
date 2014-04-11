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

var GroupModel = Model.extend({
    urlRoot: "/tps/rest/admin/groups",
    parseResponse: function(response) {
        return {
            id: response.id,
            groupID: response.GroupID,
            description: response.Description
        };
    },
    createRequest: function(attributes) {
        return {
            id: this.id,
            GroupID: attributes.groupID,
            Description: attributes.description
        };
    }
});

var GroupCollection = Collection.extend({
    model: GroupModel,
    urlRoot: "/tps/rest/admin/groups",
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        return new GroupModel({
            id: entry.id,
            groupID: entry.GroupID,
            description: entry.Description
        });
    }
});

var GroupPage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        GroupPage.__super__.initialize.call(self, options);
        self.parentPage = options.parentPage;
    },
    close: function() {
        var self = this;
        if (self.parentPage) {
            self.parentPage.open();
        } else {
            GroupPage.__super__.close.call(self);
        }
    }
});

var GroupsTable = ModelTable.extend({
    initialize: function(options) {
        var self = this;
        GroupsTable.__super__.initialize.call(self, options);
        self.parentPage = options.parentPage;
    },
    open: function(item, column) {
        var self = this;

        var page = new GroupPage({
            el: self.parentPage.$el,
            url: "group.html",
            model: self.collection.get(item.entry.id),
            editable: ["description"]
        });

        page.open();
    },
    add: function() {
        var self = this;

        var page = new GroupPage({
            el: self.parentPage.$el,
            url: "group.html",
            model: new GroupModel(),
            mode: "add",
            editable: ["groupID", "description"],
            parentPage: self.parentPage
        });

        page.open();
    }
});

var GroupsPage = Page.extend({
    load: function() {
        var self = this;

        var table = new GroupsTable({
            el: $("table[name='groups']"),
            collection: new GroupCollection(),
            parentPage: self
        });

        table.render();
    }
});
