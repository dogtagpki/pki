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

var TPSUserProfilesTableItem = TableItem.extend({
    initialize: function(options) {
        var self = this;
        TPSUserProfilesTableItem.__super__.initialize.call(self, options);
    },
    renderColumn: function(td, templateTD) {
        var self = this;

        TPSUserProfilesTableItem.__super__.renderColumn.call(self, td, templateTD);

        $("a", td).click(function(e) {
            e.preventDefault();
            self.table.open(self);
        });
    }
});

var TPSUserProfilesTable = Table.extend({
    initialize: function(options) {
        var self = this;
        options.tableItem = TPSUserProfilesTableItem;
        TPSUserProfilesTable.__super__.initialize.call(self, options);
    },
    sort: function() {
        var self = this;

        // sort profiles by id
        self.filteredEntries = _.sortBy(self.filteredEntries, function(entry) {
            return entry.id;
        });
    },
    add: function() {
        var self = this;

        profiles = new ProfileCollection();
        profiles.fetch({
            success: function(collection, response, options) {

                var dialog = self.addDialog;
                var select = dialog.$(".modal-body select").empty();

                $('<option/>', {
                    text: 'All Profiles',
                    selected: true
                }).appendTo(select);

                profiles.each(function(profile) {

                    if (_.find(self.entries, function(e) { return e.id == profile.id; })) {
                        // profile already exists

                    } else {
                        // show profile option
                        $('<option/>', {
                            text: profile.id
                        }).appendTo(select);
                    }
                });

                TPSUserProfilesTable.__super__.add.call(self);
            }
        });
    },
    addEntry: function(entry) {
        var self = this;

        if (entry.id == 'All Profiles') {
            // replace existing profiles
            self.entries = [];
            self.entries.push(entry);

        } else if (_.find(self.entries, function(e) { return e.id == entry.id; })) {
            // profile already exists

        } else {
            // add new profile
            self.entries.push(entry);
        }
    },
    remove: function(items) {
        var self = this;

        // remove selected profiles
        self.entries = _.reject(self.entries, function(entry) {
            return _.contains(items, entry.id);
        });

        // redraw table
        self.render();
    },
    renderControls: function() {
        var self = this;

        TPSUserProfilesTable.__super__.renderControls.call(self);

        if (self.mode == "edit") {

            if (_.find(self.entries, function(e) { return e.id == 'All Profiles'; })) {
                self.addButton.hide();

            } else {
                self.addButton.show();
            }
        }
    }
});

var TPSUserPage = UserPage.extend({
    initialize: function(options) {
        var self = this;
        TPSUserPage.__super__.initialize.call(self, options);
    },
    setup: function() {
        var self = this;

        TPSUserPage.__super__.setup.call(self);

        var addProfileDialog = new Dialog({
            el: self.$("#user-profile-dialog"),
            title: "Add Profile",
            actions: ["cancel", "add"]
        });

        self.profilesSection = self.$("[name='profiles']");
        self.profilesList = $("[name='list']", self.profilesSection);

        self.profilesTable = new TPSUserProfilesTable({
            el: self.profilesList,
            addDialog: addProfileDialog,
            pageSize: 10,
            parent: self
        });
    },
    saveFields: function() {
        var self = this;

        TPSUserPage.__super__.saveFields.call(self);

        var attributes = self.entry.attributes;
        attributes.tpsProfiles = self.getProfiles().join();
    },
    renderContent: function() {
        var self = this;

        TPSUserPage.__super__.renderContent.call(self);

        if (self.mode == "add") {
            self.profilesTable.mode = "edit";

        } else if (self.mode == "edit") {
            self.profilesTable.mode = "edit";

        } else { // self.mode == "view"
            self.profilesTable.mode = "view";
        }

        var profiles = [];
        var attributes = self.entry.attributes;
        if (attributes) {
            var value = attributes.tpsProfiles;
            if (value) {
                profiles = value.split(',');
            }
        }

        self.setProfiles(profiles);
    },
    setProfiles: function(profiles) {
        var self = this;

        self.profilesTable.entries = [];
        _.each(profiles, function(profile) {
            self.profilesTable.entries.push({ id: profile });
        });

        self.profilesTable.render();
    },
    getProfiles: function() {
        var self = this;

        var profiles = [];
        _.each(self.profilesTable.entries, function(profile) {
            profiles.push(profile.id);
        });

        return profiles;
    }
});
