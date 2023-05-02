//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

var AppModel = Backbone.Model.extend({});

var AppCollection = Backbone.Collection.extend({
    model: AppModel,
    url: '/pki/rest/apps'
});
