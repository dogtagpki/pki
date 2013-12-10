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

var Model = Backbone.Model.extend({
    parseResponse: function(response) {
        return response;
    },
    parse: function(response, options) {
        return this.parseResponse(response);
    },
    createRequest: function(attributes) {
        return attributes;
    },
    save: function(attributes, options) {
        var self = this;
        if (attributes == undefined) attributes = self.attributes;
        var request = self.createRequest(attributes);
        Model.__super__.save.call(self, request, options);
    }
});

var Collection = Backbone.Collection.extend({
    urlRoot: null,
    initialize: function(options) {
        var self = this;

        // convert options into URL query
        var query = "";
        _(options).each(function(value, name) {
            query = query == "" ? "?" : query + "&";
            query = query + name + "=" + encodeURIComponent(value);
        });

        self.options = options;
        self.currentURL = self.urlRoot + query;
        self.links = {};
    },
    url: function() {
        return this.currentURL;
    },
    parse: function(response) {
        var self = this;

        // parse links
        var links = self.getLinks(response);
        links = links == undefined ? [] : [].concat(links);
        self.parseLinks(links);

        // convert entries into models
        var models = [];
        var entries = self.getEntries(response);
        entries = entries == undefined ? [] : [].concat(entries);

        _(entries).each(function(entry) {
            var model = self.parseEntry(entry);
            models.push(model);
        });

        return models;
    },
    getEntries: function(response) {
        return null;
    },
    getLinks: function(response) {
        return null;
    },
    parseEntry: function(entry) {
        return null;
    },
    parseLinks: function(links) {
        var self = this;
        self.links = {};
        _(links).each(function(link) {
            var name = link["@rel"];
            var href = link["@href"];
            self.links[name] = href;
        });
    },
    link: function(name) {
        return this.links[name];
    },
    go: function(name) {
        if (this.links[name] == undefined) return;
        this.currentURL = this.links[name];
    }
});

var Dialog = Backbone.View.extend({
    initialize: function(options) {
        var self = this;
        Dialog.__super__.initialize.call(self, options);

        self.title = options.title;

        self.readonly = options.readonly;
        // by default all fields are editable
        if (self.readonly == undefined) self.readonly = [];

        self.actions = options.actions;
        if (self.actions == undefined) {
            // by default all buttons are active
            self.actions = [];
            self.$("button").each(function(index) {
                var button = $(this);
                var action = button.attr("name");
                self.actions.push(action);
            });
        }
    },
    render: function() {
        var self = this;

        if (self.title) {
            self.$("header h1").text(self.title);
        }

        self.$(".rcue-button-close").click(function(e) {
            self.close();
            e.preventDefault();
        });

        $("input", self.$el).each(function(index) {
            var input = $(this);

            self.loadField(input);

            // mark some fields readonly
            var name = input.attr("name");
            if ( _.contains(self.readonly, name)) {
                input.attr("readonly", "readonly");
            }
        });

        self.$("button").each(function(index) {
            var button = $(this);
            var action = button.attr("name");

            if (_.contains(self.actions, action)) {
                // enable buttons for specified actions
                button.click(function(e) {
                    self.performAction(action);
                    e.preventDefault();
                });
            } else {
                // hide unused buttons
                button.hide();
            }
        });
    },
    performAction: function(action) {
        var self = this;

        if (action == "save") {
            // save changes
            self.save({
                success: function(model, response, options) {
                    self.close();
                },
                error: function(model, response, options) {
                    if (response.status == 200) {
                        self.close();
                        return;
                    }
                    alert("ERROR: " + response.responseText);
                }
            });

        } else {
            self.close();
        }
    },
    open: function() {
        var self = this;

        // load data
        self.model.fetch({
            success: function(model, response, options) {
                self.render();
                self.$el.show();
            },
            error: function(model, response, options) {
                alert("ERROR: " + response);
            }
        });
    },
    close: function() {
        this.$el.hide();
    },
    loadField: function(input) {
        var self = this;
        var name = input.attr("name");
        var value = self.model.get(name);
        input.val(value);
    },
    save: function(options) {
        var self = this;

        var attributes = {};
        $("input", self.$el).each(function(index) {
            var input = $(this);
            self.saveField(input, attributes);
        });
        self.model.set(attributes);

        var changedAttributes = self.model.changedAttributes();
        if (!changedAttributes) return;

        // save changed attributes only
        self.model.save(changedAttributes, {
            patch: true,
            wait: true,
            success: options.success,
            error: options.error
        });
    },
    saveField: function(input, attributes) {
        var self = this;
        var name = input.attr("name");
        var value = input.val();
        attributes[name] = value;
    }
});

var TableItemView = Backbone.View.extend({
    initialize: function(options) {
        var self = this;
        TableItemView.__super__.initialize.call(self, options);
        self.table = options.table;
    },
    render: function() {
        var self = this;
        $("td", self.el).each(function(index) {
            var item = $(this);
            var name = item.attr("name");
            var value = self.model.get(name);

            if (name == "id") {
                item.empty();
                $("<a/>", {
                    href: "#",
                    text: value,
                    click: function(e) {
                        var dialog = self.table.editDialog;
                        dialog.model = self.model;
                        dialog.open();
                        e.preventDefault();
                    }
                }).appendTo(item);
            } else {
                item.text(value);
                self.model.on("change:" + name, function(event) {
                    item.text(self.model.get(name));
                });
            }
        });
    }
});

var TableView = Backbone.View.extend({
    initialize: function(options) {
        var self = this;

        TableView.__super__.initialize.call(self, options);
        self.editDialog = options.editDialog;

        self.tbody = $("tbody", self.el);
        self.template = $("tr", self.tbody).detach();

        // attach link handlers
        self.tfoot = $("tfoot", self.el);
        $("a.prev", self.tfoot).click(function(e) {
            if (self.collection.link("prev") == undefined) return;
            self.collection.go("prev");
            self.render();
            e.preventDefault();
        });
        $("a.next", self.tfoot).click(function(e) {
            if (self.collection.link("next") == undefined) return;
            self.collection.go("next");
            self.render();
            e.preventDefault();
        });

        self.render();
    },
    render: function() {
        var self = this;
        self.collection.fetch({
            success: function() {
                self.tbody.empty();

                // display result page
                _(self.collection.models).each(function(item) {
                    var itemView = new TableItemView({
                        el: self.template.clone(),
                        table: self,
                        model: item
                    });
                    itemView.render();
                    self.tbody.append(itemView.el);
                }, self);

                // add blank lines
                if (self.collection.options.size != undefined) {
                    var blanks = self.collection.options.size - self.collection.models.length;
                    for (var i = 0; i < blanks; i++) {
                        self.tbody.append(self.template.clone());
                    }
                }
            }
        });
    }
});
