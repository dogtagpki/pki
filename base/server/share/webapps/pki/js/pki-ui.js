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

var TableItemView = Backbone.View.extend({
    render: function() {
        var self = this;
        $("td", self.el).each(function(index) {
            var item = $(this);
            var name = item.attr("name");
            var value = self.model.get(name);
            item.text(value);
        });
    }
});

var TableView = Backbone.View.extend({
    initialize: function() {
        var self = this;

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
