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
            id: response.id,
            profileID: response.id,
            status: response.Status,
            properties: response.Properties.Property
        };
    },
    createRequest: function(attributes) {
        return {
            id: attributes.profileID,
            Status: attributes.status,
            Properties: {
                Property: attributes.properties
            }
        };
    },
    changeStatus: function(action, options) {
        var self = this;
        $.ajax({
            type: "POST",
            url: self.url() + "?action=" + action,
            dataType: "json"
        }).done(function(data, textStatus, jqXHR) {
            self.set(self.parseResponse(data));
            if (options.success) options.success.call(self, data, textStatus, jqXHR);
        }).fail(function(jqXHR, textStatus, errorThrown) {
            if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
        });
    }
});

var ProfileCollection = Collection.extend({
    urlRoot: "/tps/rest/profiles",
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        return new ProfileModel({
            id: entry.id,
            status: entry.Status
        });
    }
});

var ProfilesTable = ModelTable.extend({
    initialize: function(options) {
        var self = this;
        ProfilesTable.__super__.initialize.call(self, options);
    },
    add: function() {
        var self = this;

        window.location.hash = "#new-profile";
    }
});

var ProfilePage = ConfigEntryPage.extend({
    renderContent: function() {
        var self = this;

        ProfilePage.__super__.renderContent.call(self);

        var roles = tps.user.Roles.Role;
        var status = self.entry.status;

        if (_.contains(roles, "Administrators")) {

            // admins can edit disabled entries
            if (status == "Disabled") {
                self.editAction.show();
            } else {
                self.editAction.hide();
            }

        } else {
            self.editAction.hide();
        }

        if (_.contains(roles, "TPS Agents")) {

            // agents can enable or disable entries
            if (status == "Disabled") {
                self.approveAction.hide();
                self.rejectAction.hide();
                self.enableAction.show();
                self.disableAction.hide();

            } else if (status == "Enabled") {
                self.approveAction.hide();
                self.rejectAction.hide();
                self.enableAction.hide();
                self.disableAction.show();

            } else if (status == "Pending_Approval") {
                self.approveAction.show();
                self.rejectAction.show();
                self.enableAction.hide();
                self.disableAction.hide();

            } else {
                self.approveAction.hide();
                self.rejectAction.hide();
                self.enableAction.hide();
                self.disableAction.hide();
            }

            self.submitAction.hide();
            self.cancelAction.hide();

        } else if (_.contains(roles, "Administrators")) {

            // admins can submit or cancel entries
            if (status == "Disabled") {
                self.submitAction.show();
                self.cancelAction.hide();

            } else if (status == "Pending_Approval") {
                self.submitAction.hide();
                self.cancelAction.show();

            } else {
                self.submitAction.hide();
                self.cancelAction.hide();
            }

            self.approveAction.hide();
            self.rejectAction.hide();
            self.enableAction.hide();
            self.disableAction.hide();

        } else {
            self.enableAction.hide();
            self.disableAction.hide();
            self.approveAction.hide();
            self.rejectAction.hide();
            self.submitAction.hide();
            self.cancelAction.hide();
        }
    }
});

var ProfilesPage = Page.extend({
    load: function() {
        var self = this;

        var table = new ProfilesTable({
            el: $("table[name='profiles']"),
            collection: new ProfileCollection(),
            parent: self
        });

        table.render();
    }
});
