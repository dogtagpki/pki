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
        var attributes = response.User.Attributes.Attribute;
        attributes = attributes == undefined ? [] : [].concat(attributes);

        var attrs = {};
        _(attributes).each(function(attribute) {
            var name = attribute["@name"];
            var value = attribute["$"];
            attrs[name] = value;
        });

        return {
            id: response.User["@id"],
            fullName: response.User.FullName,
            email: response.User.Email,
            state: response.User.State,
            type: response.User.Type,
            attributes: attrs
        };
    },
    createRequest: function(attributes) {
        var attrs = [];
        _(attributes.attributes).each(function(value, name) {
            attrs.push({
                Attribute: {
                    "@name": name,
                    "$": value
                }
            });
        });

        return {
            User: {
                "@id": attributes.id,
                FullName: attributes.fullName,
                Email: attributes.email,
                State: attributes.state,
                Type: attributes.type,
                Attributes: attrs
            }
        };
    }
});

var UserCollection = Collection.extend({
    urlRoot: "/tps/rest/admin/users",
    getEntries: function(response) {
        return response.Users.User;
    },
    getLinks: function(response) {
        return response.Users.Link;
    },
    parseEntry: function(entry) {
        return new UserModel({
            id: entry["@id"],
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
        var value = attributes.tpsProfiles;
        input.val(value);
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
