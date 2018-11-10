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
    initialize: function(attrs, options) {
        var self = this;
        UserModel.__super__.initialize.call(self, attrs, options);
        options = options || {};
        self.urlRoot = options.urlRoot;
    },
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
    initialize: function(models, options) {
        var self = this;
        UserCollection.__super__.initialize.call(self, models, options);
        options = options || {};
        self.urlRoot = options.urlRoot;
    },
    model: function(attrs, options) {
        var self = this;
        options.urlRoot = self.urlRoot;
        return new UserModel(attrs, options);
    },
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        var self = this;
        return new UserModel({
            id: entry.id,
            userID: entry.UserID,
            fullName: entry.FullName
        }, {
            urlRoot: self.urlRoot
        });
    }
});

var UserRoleModel = Model.extend({
    initialize: function(attrs, options) {
        var self = this;
        UserRoleModel.__super__.initialize.call(self, attrs, options);
        options = options || {};
        self.urlRoot = options.urlRoot;
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
        self.urlRoot = options.urlRoot;
    },
    getEntries: function(response) {
        return response.Membership;
    },
    getLinks: function(response) {
        return response.Link;
    },
    model: function(attrs, options) {
        var self = this;
        return new UserRoleModel({
            userID: self.userID
        }, {
            urlRoot: self.urlRoot
        });
    },
    parseEntry: function(entry) {
        var self = this;
        return new UserRoleModel({
            id: entry.id,
            roleID: entry.id,
            userID: entry.UserID
        }, {
            urlRoot: self.urlRoot
        });
    }
});

var UserCertModel = Model.extend({
    initialize: function(attrs, options) {
        var self = this;
        UserCertModel.__super__.initialize.call(self, attrs, options);
        options = options || {};
        self.urlRoot = options.urlRoot;
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
        self.urlRoot = options.urlRoot;
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
        }, {
            urlRoot: self.urlRoot
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
        }, {
            urlRoot: self.urlRoot
        });
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
    },
    renderContent: function() {
        var self = this;
        UserPage.__super__.renderContent.call(self);
    },
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
    initialize: function(options) {
        var self = this;
        UsersPage.__super__.initialize.call(self, options);
        options = options || {};
        self.collection = options.collection;
    },
    load: function() {
        var self = this;

        var table = new UsersTable({
            el: $("table[name='users']"),
            collection: self.collection
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
