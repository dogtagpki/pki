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

var UserRoleModel = Model.extend({
    url: function() {
        var self = this;

        var userID = self.get("userID");
        var url = "/tps/rest/admin/users/" + userID + "/memberships";

        if (self.id) url = url + "/" + self.id;

        return url;
    },
    parseResponse: function(response) {
        return {
            id: response.id,
            roleID: response.id,
            userID: response.UserID
        };
    },
    createRequest: function(entry) {
        return {
            id: entry.roleID,
            UserID: entry.userID
        };
    },
    save: function(attributes, options) {
        var self = this;
        $.ajax({
            type: "POST",
            url: self.url(),
            dataType: "json",
            data: attributes.roleID,
        }).done(function(data, textStatus, response) {
            self.set(self.parseResponse(data));
            if (options.success) options.success.call(self, self, response, options);
        }).fail(function(response, textStatus, errorThrown) {
            if (options.error) options.error.call(self, self, response, options);
        });
    }
});

var UserRoleCollection = Collection.extend({
    initialize: function(models, options) {
        var self = this;
        UserRoleCollection.__super__.initialize.call(self, models, options);
        options = options || {};
        self.userID = options.userID;
        self.urlRoot = "/tps/rest/admin/users/" + self.userID + "/memberships";
    },
    getEntries: function(response) {
        return response.Membership;
    },
    getLinks: function(response) {
        return response.Link;
    },
    model: function(attrs, options) {
        return new UserRoleModel({
            userID: this.userID
        });
    },
    parseEntry: function(entry) {
        return new UserRoleModel({
            id: entry.id,
            roleID: entry.id,
            userID: entry.UserID
        });
    }
});

var UserCertModel = Model.extend({
    url: function() {
        var self = this;

        var userID = self.get("userID");
        var url = "/tps/rest/admin/users/" + userID + "/certs";

        if (self.id) url = url + "/" + encodeURIComponent(self.id);

        return url;
    },
    parseResponse: function(response) {
        return {
            id: response.id,
            certID: response.id,
            serialNumber: response.SerialNumber,
            subjectDN: response.SubjectDN,
            issuerDN: response.IssuerDN,
            userID: response.UserID
        };
    },
    createRequest: function(entry) {
        return {
            Encoded: entry.encoded
        };
    },
    save: function(attributes, options) {
        var self = this;
        var request = self.createRequest(attributes);
        $.ajax({
            type: "POST",
            url: self.url(),
            dataType: "json",
            contentType: "application/json",
            data: JSON.stringify(request),
        }).done(function(data, textStatus, response) {
            self.set(self.parseResponse(data));
            if (options.success) options.success.call(self, self, response, options);
        }).fail(function(response, textStatus, errorThrown) {
            if (options.error) options.error.call(self, self, response, options);
        });
    }
});

var UserCertCollection = Collection.extend({
    initialize: function(models, options) {
        var self = this;
        UserCertCollection.__super__.initialize.call(self, models, options);
        options = options || {};
        self.userID = options.userID;
        self.urlRoot = "/tps/rest/admin/users/" + self.userID + "/certs";
    },
    getEntries: function(response) {
        return response.Cert;
    },
    getLinks: function(response) {
        return response.Link;
    },
    model: function(attrs, options) {
        var self = this;
        return new UserCertModel({
            userID: self.userID
        });
    },
    parseEntry: function(entry) {
        var self = this;
        return new UserCertModel({
            id: entry.id,
            certID: entry.id,
            serialNumber: entry.SerialNumber,
            subjectDN: entry.SubjectDN,
            issuerDN: entry.IssuerDN,
            userID: self.userID
        });
    }
});

var UserProfilesTableItem = TableItem.extend({
    initialize: function(options) {
        var self = this;
        UserProfilesTableItem.__super__.initialize.call(self, options);
    },
    renderColumn: function(td, templateTD) {
        var self = this;

        UserProfilesTableItem.__super__.renderColumn.call(self, td, templateTD);

        $("a", td).click(function(e) {
            e.preventDefault();
            self.table.open(self);
        });
    }
});

var UserProfilesTable = Table.extend({
    initialize: function(options) {
        var self = this;
        options.tableItem = UserProfilesTableItem;
        UserProfilesTable.__super__.initialize.call(self, options);
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

                UserProfilesTable.__super__.add.call(self);
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

        UserProfilesTable.__super__.renderControls.call(self);

        if (self.mode == "edit") {

            if (_.find(self.entries, function(e) { return e.id == 'All Profiles'; })) {
                self.addButton.hide();

            } else {
                self.addButton.show();
            }
        }
    }
});

var UserPage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        UserPage.__super__.initialize.call(self, options);
    },
    setup: function() {
        var self = this;

        UserPage.__super__.setup.call(self);

        var addProfileDialog = new Dialog({
            el: self.$("#user-profile-dialog"),
            title: "Add Profile",
            actions: ["cancel", "add"]
        });

        self.profilesSection = self.$("[name='profiles']");
        self.profilesList = $("[name='list']", self.profilesSection);

        self.profilesTable = new UserProfilesTable({
            el: self.profilesList,
            addDialog: addProfileDialog,
            pageSize: 10,
            parent: self
        });

        self.showRolesAction = $("[name='showRoles']", self.viewMenu);

        $("a", self.showRolesAction).click(function(e) {
            e.preventDefault();
            window.location.hash = window.location.hash + "/roles";
        });

        self.showCertsAction = $("[name='showCerts']", self.viewMenu);

        $("a", self.showCertsAction).click(function(e) {
            e.preventDefault();
            window.location.hash = window.location.hash + "/certs";
        });
    },
    saveFields: function() {
        var self = this;

        UserPage.__super__.saveFields.call(self);

        var attributes = self.entry.attributes;
        if (attributes == undefined) {
            attributes = {};
            self.entry.attributes = attributes;
        }
        attributes.tpsProfiles = self.getProfiles().join();
    },
    renderContent: function() {
        var self = this;

        UserPage.__super__.renderContent.call(self);

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

var UsersTable = ModelTable.extend({
    initialize: function(options) {
        var self = this;
        UsersTable.__super__.initialize.call(self, options);
    },
    add: function() {
        var self = this;

        window.location.hash = "#new-user";
    }
});

var UsersPage = Page.extend({
    load: function() {
        var self = this;

        var table = new UsersTable({
            el: $("table[name='users']"),
            collection: new UserCollection()
        });

        table.render();
    }
});

var UserRolesPage = Page.extend({
    load: function() {
        var self = this;

        if (self.collection && self.collection.options && self.collection.options.userID) {
            $(".breadcrumb li[name='user'] a")
                .attr("href", "#users/" + self.collection.options.userID)
                .text("User " + self.collection.options.userID);
            $(".pki-title").text("Roles for User " + self.collection.options.userID);
        }

        var addRoleDialog = new Dialog({
            el: self.$("#user-role-dialog"),
            title: "Add Role",
            readonly: ["userID"],
            actions: ["cancel", "add"]
        });

        var table = new ModelTable({
            el: self.$("table[name='roles']"),
            pageSize: 10,
            addDialog: addRoleDialog,
            collection: self.collection
        });

        table.render();
    }
});

var UserCertsPage = Page.extend({
    load: function() {
        var self = this;

        if (self.collection && self.collection.options && self.collection.options.userID) {
            $(".breadcrumb li[name='user'] a")
                .attr("href", "#users/" + self.collection.options.userID)
                .text("User " + self.collection.options.userID);
            $(".pki-title").text("Certificates for User " + self.collection.options.userID);
        }

        var addCertDialog = new Dialog({
            el: self.$("#user-cert-dialog"),
            title: "Add Cert",
            readonly: ["userID"],
            actions: ["cancel", "add"]
        });

        var table = new ModelTable({
            el: self.$("table[name='certs']"),
            pageSize: 10,
            addDialog: addCertDialog,
            collection: self.collection
        });

        table.render();
    }
});
