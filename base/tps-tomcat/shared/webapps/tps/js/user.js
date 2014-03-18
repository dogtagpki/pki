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

var UserModel = Model.extend({
    urlRoot: "/tps/rest/admin/users",
    parseResponse: function(response) {

        var attrs = {};
        if (response.Attributes) {
            var attributes = response.Attributes.Attribute;
            attributes = attributes == undefined ? [] : [].concat(attributes);

            _(attributes).each(function(attribute) {
                var name = attribute.name;
                var value = attribute.value;
                attrs[name] = value;
            });
        }

        return {
            id: response.id,
            userID: response.UserID,
            fullName: response.FullName,
            email: response.Email,
            state: response.State,
            type: response.Type,
            attributes: attrs
        };
    },
    createRequest: function(attributes) {
        var attrs = [];
        _(attributes.attributes).each(function(value, name) {
            attrs.push({
                name: name,
                value: value
            });
        });

        return {
            id: this.id,
            UserID: attributes.userID,
            FullName: attributes.fullName,
            Email: attributes.email,
            State: attributes.state,
            Type: attributes.type,
            Attributes: {
                Attribute: attrs
            }
        };
    }
});

var UserCollection = Collection.extend({
    model: UserModel,
    urlRoot: "/tps/rest/admin/users",
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        return new UserModel({
            id: entry.id,
            userID: entry.UserID,
            fullName: entry.FullName
        });
    }
});

var UserDialog = Dialog.extend({
    loadField: function(input) {
        var self = this;

        var name = input.attr("name");
        if (name != "tpsProfiles") {
            UserDialog.__super__.loadField.call(self, input);
            return;
        }

        var attributes = self.model.get("attributes");
        if (attributes) {
            var value = attributes.tpsProfiles;
            input.val(value);
        }
    },
    saveField: function(input, attributes) {
        var self = this;

        var name = input.attr("name");
        if (name != "tpsProfiles") {
            UserDialog.__super__.saveField.call(self, input, attributes);
            return;
        }

        var attrs = attributes["attributes"];
        if (attrs == undefined) attrs = {};
        attrs.tpsProfiles = input.val();
        attributes["attributes"] = attrs;
    }
});

var UserPage = Page.extend({
    load: function() {
        var addDialog = new UserDialog({
            el: $("#user-dialog"),
            title: "Add User",
            readonly: ["type"],
            actions: ["cancel", "add"]
        });

        var editDialog = new UserDialog({
            el: $("#user-dialog"),
            title: "Edit User",
            readonly: ["userID", "type"],
            actions: ["cancel", "save"]
        });

        new Table({
            el: $("table[name='users']"),
            collection: new UserCollection(),
            addDialog: addDialog,
            editDialog: editDialog
        });
    }
});
