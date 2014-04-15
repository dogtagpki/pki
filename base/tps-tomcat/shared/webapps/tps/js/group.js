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

var GroupMemberModel = Model.extend({
    url: function() {
        var self = this;

        // There's an attribute name mismatch for group ID: the
        // server uses GroupID and the client uses groupID. In other
        // models the mismatch can be translated just fine, but in
        // this model it becomes a problem because the model needs
        // to construct the URL using the attribute.
        //
        // During read operation it needs to use the attribute that's
        // already translated for client (i.e. groupID), but during
        // add it needs to use the attribute meant for server (i.e.
        // GroupID). So the workaround is to read whichever available.
        var groupID = self.get("groupID");        // for read
        groupID = groupID || self.get("GroupID"); // for add

        var url = "/tps/rest/admin/groups/" + groupID + "/members";

        // append member ID for read
        if (self.id) url = url + "/" + self.id;

        return url;
    },
    parseResponse: function(response) {
        return {
            id: response.id,
            memberID: response.id,
            groupID: response.GroupID
        };
    },
    createRequest: function(entry) {
        return {
            id: entry.memberID,
            GroupID: entry.groupID
        };
    }
});

var GroupMemberCollection = Collection.extend({
    initialize: function(models, options) {
        var self = this;
        GroupMemberCollection.__super__.initialize.call(self, models, options);
        options = options || {};
        self.groupID = options.groupID;
        self.urlRoot = "/tps/rest/admin/groups/" + self.groupID + "/members";
    },
    getEntries: function(response) {
        return response.Member;
    },
    getLinks: function(response) {
        return response.Link;
    },
    model: function(attrs, options) {
        return new GroupMemberModel({
            groupID: this.groupID
        });
    },
    parseEntry: function(entry) {
        return new GroupMemberModel({
            id: entry.id,
            memberID: entry.id,
            groupID: entry.GroupID
        });
    }
});

var GroupMembersTableItem = TableItem.extend({
    initialize: function(options) {
        var self = this;
        GroupMembersTableItem.__super__.initialize.call(self, options);
    },
    renderColumn: function(td, templateTD) {
        var self = this;

        GroupMembersTableItem.__super__.renderColumn.call(self, td, templateTD);

        $("a", td).click(function(e) {
            e.preventDefault();
            self.table.open(self);
        });
    }
});

var GroupPage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        GroupPage.__super__.initialize.call(self, options);
    },
    setup: function() {
        var self = this;

        GroupPage.__super__.setup.call(self);

        var dialog = self.$("#member-dialog");

        var addDialog = new Dialog({
            el: dialog,
            title: "Add Member",
            readonly: ["groupID"],
            actions: ["cancel", "add"]
        });

        var editDialog = new Dialog({
            el: dialog,
            title: "Member",
            readonly: ["groupID", "memberID"],
            actions: ["close"]
        });

        self.membersTable = new ModelTable({
            el: self.$("table[name='members']"),
            pageSize: 10,
            addDialog: addDialog,
            editDialog: editDialog,
            tableItem: GroupMembersTableItem,
            parent: self
        });
    },
    renderContent: function() {
        var self = this;

        GroupPage.__super__.renderContent.call(self);

        // Since the members table is backed by a REST resource any
        // changes will be executed immediately even if the page is
        // in view mode. To avoid confusion, the members table will
        // be disabled in page edit mode.
        if (self.mode == "edit") {
            // In page edit mode, the members tables is read-only.
            self.membersTable.mode = "view";

        } else { // self.mode == "view"
            // In page view mode, the members table is editable.
            self.membersTable.mode = "edit";
        }

        self.membersTable.collection = new GroupMemberCollection(null, { groupID: self.entry.id });
        self.membersTable.render();
    }
});

var GroupsTable = ModelTable.extend({
    initialize: function(options) {
        var self = this;
        GroupsTable.__super__.initialize.call(self, options);
    },
    add: function() {
        var self = this;

        window.location.hash = "#new-group";
    }
});

var GroupsPage = Page.extend({
    load: function() {
        var self = this;

        var table = new GroupsTable({
            el: $("table[name='groups']"),
            collection: new GroupCollection()
        });

        table.render();
    }
});
