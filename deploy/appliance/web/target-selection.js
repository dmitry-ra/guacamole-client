/* Licensed under the Apache License, Version 2.0. See LICENSE. */
(function () {
    'use strict';

    var module = angular.module('guacPortalTargets', []);
    var FIELD = 'wrdp-target';
    var own = function (object, key) {
        return Object.prototype.hasOwnProperty.call(object, key);
    };
    var valid = function (value) {
        return typeof value === 'string' && value.length <= 48
            && !/[^a-z0-9-]/.test(value)
            && /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/.test(value);
    };

    module.factory('portalTargetSelection', ['$rootScope', '$location', function ($rootScope, $location) {
        // Deliberately tab-local: never store selection alongside the auth token.
        var selected;
        var present = false;
        var revision = 0;
        var request = 0;
        var set = function (value, exists) {
            if (present !== exists || selected !== value) {
                selected = value;
                present = exists;
                revision++;
            }
        };
        var readURL = function () {
            var query = $location.search();
            set(query[FIELD], own(query, FIELD));
        };
        readURL();

        $rootScope.$on('guacLoginPending', function (event, parameters) {
            // Upstream broadcasts the promise before registering its request
            // serialization callback. Register now, so normalization runs first.
            var started = revision;
            var latest = ++request;
            parameters.then(function (values) {
                if (started !== revision || latest !== request)
                    return;
                if (own(values, FIELD)) {
                    // An unselected native enum must not discard a direct URL.
                    if (values[FIELD] === '') {
                        if (present)
                            values[FIELD] = selected;
                        else
                            delete values[FIELD];
                    }
                    else {
                        set(values[FIELD], true);
                    }
                }
                else if (present)
                    values[FIELD] = selected;
            }, angular.noop);
        });

        $rootScope.$on('guacLogin', function () {
            // Native login reloads the route, which submits URL parameters
            // again. Keep a dropdown choice consistent with that URL in this
            // tab before the reload, including when it overrides a direct URL.
            if (present && valid(selected))
                $location.search(FIELD, selected).replace();
        });

        // Fresh explicit URL navigation is also supported with an existing token.
        $rootScope.$on('$locationChangeSuccess', readURL);

        return {
            get: function () { return { present: present, alias: selected, revision: revision }; }
        };
    }]);

    module.run(['portalTargetSelection', angular.noop]);

    module.config(['$provide', function ($provide) {
        $provide.decorator('formService', ['$delegate', '$compile', '$q', '$controller', 'portalTargetSelection',
            function (service, $compile, $q, $controller, selection) {
                var nativeInsert = service.insertFieldElement;
                service.insertFieldElement = function (container, type, scope) {
                    if (type !== 'ENUM' || scope.namespace !== 'LOGIN'
                            || !scope.field || scope.field.name !== FIELD)
                        return nativeInsert.apply(service, arguments);
                    // Render only validated aliases as escaped text through
                    // ng-options. Do not translate aliases as arbitrary keys.
                    scope.portalTargetOptions = (scope.field.options || []).filter(valid);
                    var target = selection.get();
                    if (!scope.model && target.present && valid(target.alias)
                            && scope.portalTargetOptions.indexOf(target.alias) !== -1)
                        scope.model = target.alias;
                    var labeled = typeof container.closest === 'function' && container.closest('.labeled-field');
                    if (labeled)
                        labeled.classList.add('portal-target-labeled-field');
                    container.innerHTML = '<div class="select-field portal-target-select"><select ng-attr-id="{{ fieldId }}"'
                        + ' ng-attr-name="{{ field.name }}" ng-disabled="disabled" guac-focus="focused"'
                        + ' ng-model="model" ng-options="option as option for option in portalTargetOptions"></select></div>';
                    $controller('selectFieldController', { $scope: scope });
                    return $q.resolve($compile(container.childNodes)(scope));
                };
                return service;
            }]);
        $provide.decorator('userPageService', ['$delegate', '$injector', function (service, $injector) {
            var nativeHome = service.getHomePage;
            var selection = $injector.get('portalTargetSelection');
            var $q = $injector.get('$q');
            var $rootScope = $injector.get('$rootScope');
            var authentication = $injector.get('authenticationService');
            var groups = $injector.get('connectionGroupService');
            var ConnectionGroup = $injector.get('ConnectionGroup');
            var ClientIdentifier = $injector.get('ClientIdentifier');
            var PageDefinition = $injector.get('PageDefinition');

            var pending = function () { return $q.defer().promise; };
            var current = function (target) { return selection.get().revision === target.revision; };
            var stop = function (target) {
                // A stale lookup must neither navigate nor replace B's UI with
                // an error from A, regardless of lookup completion order.
                if (current(target))
                    $rootScope.$broadcast('guacFatalPageError', {
                        type: 'PERMISSION_DENIED',
                        message: 'Selected target is invalid or unavailable.',
                        translatableMessage: { key: 'PORTAL.ERROR_TARGET_UNAVAILABLE' }
                    });
                // Native rejection falls through to home; route success clears
                // fatal errors. Keep failures pending like native DIE handling.
                return pending();
            };

            service.getHomePage = function () {
                var target = selection.get();
                var args = arguments;
                return $q.resolve().then(function () {
                    if (!current(target))
                        return pending();
                    if (!target.present)
                        // Preserve native permission/tree loading and failure
                        // handling, but always show the connection chooser.
                        // A general portal entry must not auto-connect even
                        // when the native default is one available session.
                        return $q.resolve(nativeHome.apply(service, args)).then(function () {
                            return new PageDefinition({
                                name: 'USER_MENU.ACTION_NAVIGATE_HOME',
                                url: '/'
                            });
                        });
                    if (!valid(target.alias)
                            || authentication.getAvailableDataSources().indexOf('postgresql') === -1)
                        return stop(target);
                    return groups.getConnectionGroupTree('postgresql', ConnectionGroup.ROOT_IDENTIFIER, ['READ'])
                        .then(function (tree) {
                            if (!current(target))
                                return pending();
                            var matches = [];
                            var visit = function (group) {
                                if (!group || typeof group !== 'object'
                                        || (group.childConnections !== undefined && !Array.isArray(group.childConnections))
                                        || (group.childConnectionGroups !== undefined && !Array.isArray(group.childConnectionGroups)))
                                    throw new Error('Invalid connection tree');
                                (group.childConnections || []).forEach(function (connection) {
                                    if (!connection || typeof connection !== 'object')
                                        throw new Error('Invalid connection');
                                    if (connection.name === target.alias)
                                        matches.push(connection);
                                });
                                (group.childConnectionGroups || []).forEach(visit);
                            };
                            visit(tree);
                            // JDBC numeric identifiers are server-assigned and
                            // nonempty decimal strings, never URL/control data.
                            if (matches.length !== 1 || typeof matches[0].identifier !== 'string'
                                    || !/^[0-9]+$/.test(matches[0].identifier)
                                    || /[^0-9]/.test(matches[0].identifier))
                                return stop(target);
                            return new PageDefinition({
                                name: matches[0].name,
                                url: '/client/' + ClientIdentifier.toString({
                                    dataSource: 'postgresql',
                                    type: ClientIdentifier.Types.CONNECTION,
                                    id: matches[0].identifier
                                })
                            });
                        });
                }).then(function (page) {
                    return current(target) ? page : pending();
                }).catch(function () { return stop(target); });
            };
            return service;
        }]);
    }]);

    angular.module('index').requires.push('guacPortalTargets');
}());
