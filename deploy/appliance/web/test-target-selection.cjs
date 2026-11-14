/* Licensed under the Apache License, Version 2.0. See LICENSE. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const root = path.resolve(__dirname, '../../..');
function tab(query = {}, connections = [{ name: 'desktop-a', identifier: '71' },
    { name: 'desktop-b', identifier: '900' }]) {
    const factories = {}, configs = [], runs = [], listeners = {}, events = [], lookups = [];
    const modules = {};
    const angular = { noop() {}, module(name) {
        return modules[name] ||= { requires: [],
            factory(n, f) { factories[n] = f; return this; },
            config(f) { configs.push(f); return this; },
            run(f) { runs.push(f); return this; } };
    } };
    const scope = {
        $on(name, callback) { (listeners[name] ||= []).push(callback); },
        $broadcast(name, ...args) {
            events.push([name, ...args]);
            for (const callback of listeners[name] || []) callback({}, ...args);
        }
    };
    let available = ['postgresql'], failLookup = false, defaults = 0, treeOverride;
    let encodeFailure = false;
    const lookupQueue = [], nativeQueue = [], compiled = [];
    const location = {
        search(key, value) {
            if (!arguments.length) return query;
            query[key] = value; return this;
        }, replace() { return this; }
    };
    const services = {
        $rootScope: scope, $location: location, $q: {
            resolve: Promise.resolve.bind(Promise),
            defer: () => ({ promise: new Promise(() => {}) })
        },
        $window: {
            btoa: value => {
                if (encodeFailure) throw new Error('encoding failure');
                return Buffer.from(value, 'binary').toString('base64');
            },
            atob: value => Buffer.from(value, 'base64').toString('binary')
        },
        authenticationService: { getAvailableDataSources: () => available },
        ConnectionGroup: { ROOT_IDENTIFIER: 'ROOT' },
        connectionGroupService: {
            getConnectionGroupTree(...args) {
                lookups.push(args);
                if (lookupQueue.length) return lookupQueue.shift();
                return failLookup ? Promise.reject(new Error('denied')) : Promise.resolve(treeOverride !== undefined ? treeOverride : {
                    childConnections: [], childConnectionGroups: [{ childConnections: connections }]
                });
            }
        }
    };
    const invoke = binding => binding.at(-1)(...binding.slice(0, -1).map(get));
    function get(name) {
        if (name === '$injector') return { get };
        if (!(name in services)) services[name] = invoke(factories[name]);
        return services[name];
    }
    const context = vm.createContext({ angular });
    // Exercise the real upstream native page and client identifier factories.
    for (const file of ['guacamole/src/main/frontend/src/app/navigation/types/ClientIdentifier.js',
        'guacamole/src/main/frontend/src/app/navigation/types/PageDefinition.js',
        'deploy/appliance/web/target-selection.js'])
        vm.runInContext(fs.readFileSync(path.join(root, file), 'utf8'), context);
    for (const run of runs) invoke(run);
    const nativeHome = { getHomePage() {
        defaults++;
        return nativeQueue.length ? nativeQueue.shift() : Promise.resolve({ url: '/native' });
    } };
    const nativeForm = { insertFieldElement() { return 'native-form'; } };
    services.$compile = nodes => scope => { compiled.push({ nodes, scope }); return nodes; };
    services.$controller = (name, locals) => {
        assert.equal(name, 'selectFieldController');
        locals.$scope.model ||= '';
    };
    services.$provide = { decorator(name, binding) {
        assert.ok(['userPageService', 'formService'].includes(name));
        services.$delegate = name === 'userPageService' ? nativeHome : nativeForm;
        services[name === 'userPageService' ? 'home' : 'form'] = invoke(binding);
    } };
    for (const config of configs) invoke(config);
    return {
        events, lookups, scope, query,
        get defaults() { return defaults; },
        sources(value) { available = value; }, fail() { failLookup = true; },
        tree(value) { treeOverride = value; },
        lookup(promise) { lookupQueue.push(promise); },
        native(promise) { nativeQueue.push(promise); },
        encodingFails() { encodeFailure = true; },
        pendingDeferred(promise) { scope.$broadcast('guacLoginPending', promise); },
        form: (...args) => services.form.insertFieldElement(...args), compiled,
        async pending(params) {
            const promise = Promise.resolve(params);
            scope.$broadcast('guacLoginPending', promise);
            // Match upstream's registration order: broadcast before serialization.
            return promise.then(values => ({ ...values }));
        },
        home: () => services.home.getHomePage(),
        decode(page) { return get('ClientIdentifier').fromString(page.url.slice('/client/'.length)); }
    };
}

test('general portal without target shows chooser after native authorization', async () => {
    const t = tab();
    await t.pending({ token: 'synthetic' });
    assert.equal((await t.home()).url, '/');
    assert.equal(t.defaults, 1);
    assert.equal(t.lookups.length, 0);
});

test('untouched optional enum without URL intent shows chooser', async () => {
    const t = tab();
    const values = await t.pending({ username: 'test', 'wrdp-target': '' });
    assert.equal(Object.hasOwn(values, 'wrdp-target'), false);
    await t.pending({ 'totp-code': '000000' });
    assert.equal((await t.home()).url, '/');
    assert.equal(t.defaults, 1);
});

test('direct URL, blank enum, TOTP and retry preserve selection before serialization', async () => {
    const t = tab({ 'wrdp-target': 'desktop-b' });
    assert.equal((await t.pending({ username: 'test', 'wrdp-target': '' }))['wrdp-target'], 'desktop-b');
    assert.equal((await t.pending({ 'totp-code': '000000' }))['wrdp-target'], 'desktop-b');
    t.scope.$broadcast('guacLoginFailed', {}, { type: 'INVALID_CREDENTIALS' });
    assert.equal((await t.pending({ username: 'test' }))['wrdp-target'], 'desktop-b');
    t.scope.$broadcast('guacLogin', 'synthetic');
    const page = await t.home();
    const id = t.decode(page);
    assert.equal(id.id, '900'); assert.equal(id.dataSource, 'postgresql'); assert.equal(id.type, 'c');
    assert.deepEqual(Array.from(t.lookups[0], value => Array.isArray(value) ? Array.from(value) : value),
        ['postgresql', 'ROOT', ['READ']]);
});

test('dropdown overrides link and survives native route retry', async () => {
    const t = tab({ 'wrdp-target': 'desktop-a' });
    await t.pending({ username: 'test', 'wrdp-target': 'desktop-b' });
    t.scope.$broadcast('guacLogin', 'synthetic');
    assert.equal(t.query['wrdp-target'], 'desktop-b');
    await t.pending({ ...t.query, token: 'synthetic' });
    assert.equal(t.decode(await t.home()).id, '900');
});

test('two tabs have independent targets and resolve arbitrary database IDs', async () => {
    const a = tab(), b = tab();
    await Promise.all([a.pending({ 'wrdp-target': 'desktop-a' }), b.pending({ 'wrdp-target': 'desktop-b' })]);
    assert.equal(a.decode(await a.home()).id, '71');
    assert.equal(b.decode(await b.home()).id, '900');
});

for (const alias of ['', 'Desktop-a', '../desktop-a', 'https://example.invalid', 'a'.repeat(49), 'desktop-a\n',
    ['desktop-a', 'desktop-b'], true, null, 'unknown']) {
    test(`explicit invalid/unavailable target fails closed: ${JSON.stringify(alias)}`, async () => {
        const t = tab({ 'wrdp-target': alias });
        await t.pending({ ...t.query });
        await blocked(t);
        assert.equal(t.defaults, 0);
        assert.equal(t.events.filter(e => e[0] === 'guacFatalPageError').length, 1);
    });
}

test('duplicates, missing authorization and lookup failure cannot invoke default', async () => {
    const cases = [tab({ 'wrdp-target': 'desktop-a' }, [
        { name: 'desktop-a', identifier: '1' }, { name: 'desktop-a', identifier: '2' }]),
        tab({ 'wrdp-target': 'desktop-a' }, []), tab({ 'wrdp-target': 'desktop-a' }),
        tab({ 'wrdp-target': 'desktop-a' }), tab({ 'wrdp-target': 'desktop-a' }, [{ name: 'desktop-a', identifier: 1 }])];
    cases[2].sources(['other']); cases[3].fail();
    for (const t of cases) {
        await blocked(t);
        assert.equal(t.defaults, 0);
        assert.ok(t.events.some(e => e[0] === 'guacFatalPageError'));
    }
});

async function blocked(t) {
    let settled = false;
    t.home().then(() => { settled = true; }, () => { settled = true; });
    // Flush the inert lookup promise and chained callbacks without network,
    // clocks, or awaiting the intentionally unresolved route itself.
    await flush();
    assert.equal(settled, false, 'invalid target must not resolve/reject into native route fallback');
}

test('authenticated explicit URL changes use newly selected target', async () => {
    const t = tab({ 'wrdp-target': 'desktop-a' });
    assert.equal(t.decode(await t.home()).id, '71');
    t.query['wrdp-target'] = 'desktop-b';
    t.scope.$broadcast('$locationChangeSuccess');
    assert.equal(t.decode(await t.home()).id, '900');
});

async function flush() { for (let i = 0; i < 20; i++) await Promise.resolve(); }
function deferred() {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
}
function change(t, value) {
    if (value === undefined) delete t.query['wrdp-target'];
    else t.query['wrdp-target'] = value;
    t.scope.$broadcast('$locationChangeSuccess');
}

test('removing URL intent restores native home while missing continuation parameter preserves it', async () => {
    const t = tab({ 'wrdp-target': 'desktop-a' });
    assert.equal((await t.pending({ 'totp-code': '000000' }))['wrdp-target'], 'desktop-a');
    change(t, undefined);
    const params = await t.pending({ token: 'synthetic' });
    assert.equal(Object.hasOwn(params, 'wrdp-target'), false);
    assert.equal((await t.home()).url, '/');
});

for (const failOld of [false, true]) {
    test(`stale A ${failOld ? 'failure' : 'success'} cannot navigate or emit errors after B`, async () => {
        const t = tab({ 'wrdp-target': 'desktop-a' });
        const a = deferred(), b = deferred();
        t.lookup(a.promise); t.lookup(b.promise);
        let settledA = false;
        t.home().then(() => { settledA = true; }, () => { settledA = true; });
        await flush();
        change(t, 'desktop-b');
        const homeB = t.home();
        await flush();
        b.resolve({ childConnections: [{ name: 'desktop-b', identifier: '812' }] });
        assert.equal(t.decode(await homeB).id, '812');
        if (failOld) a.reject(new Error('old failure'));
        else a.resolve({ childConnections: [{ name: 'desktop-a', identifier: '14' }] });
        await flush();
        assert.equal(settledA, false);
        assert.equal(t.events.some(e => e[0] === 'guacFatalPageError'), false);
        assert.equal(t.defaults, 0);
    });
}

test('out-of-order parameter promises cannot restore stale target', async () => {
    const t = tab({ 'wrdp-target': 'desktop-a' });
    const old = deferred();
    t.pendingDeferred(old.promise);
    change(t, 'desktop-b');
    await t.pending({ 'wrdp-target': 'desktop-b', username: 'test' });
    old.resolve({ 'wrdp-target': 'desktop-a', username: 'test' });
    await flush();
    assert.equal(t.decode(await t.home()).id, '900');
});

test('late native-home completion cannot navigate over a selected target', async () => {
    const t = tab();
    const native = deferred();
    t.native(native.promise);
    let settled = false;
    t.home().then(() => { settled = true; });
    await flush();
    assert.equal(t.defaults, 1);
    change(t, 'desktop-b');
    native.resolve({ url: '/native' });
    await flush();
    assert.equal(settled, false);
    assert.equal(t.decode(await t.home()).id, '900');
});

test('latest auth parameter request wins even before either promise resolves', async () => {
    const t = tab();
    const a = deferred(), b = deferred();
    t.pendingDeferred(a.promise); t.pendingDeferred(b.promise);
    b.resolve({ 'wrdp-target': 'desktop-b' });
    await flush();
    a.resolve({ 'wrdp-target': 'desktop-a' });
    await flush();
    assert.equal(t.decode(await t.home()).id, '900');
});

test('URL removal invalidates an in-flight lookup without showing an old error', async () => {
    const t = tab({ 'wrdp-target': 'desktop-a' });
    const old = deferred();
    t.lookup(old.promise);
    let settled = false;
    t.home().then(() => { settled = true; });
    await flush();
    change(t, undefined);
    old.reject(new Error('old lookup failed'));
    await flush();
    assert.equal(settled, false);
    assert.equal(t.events.some(e => e[0] === 'guacFatalPageError'), false);
    assert.equal((await t.home()).url, '/');
});

for (const tree of [null, [], { childConnections: {} }, { childConnectionGroups: {} },
    { childConnections: [null] }, { childConnectionGroups: [null] },
    ...['', '7\n', '7\0c\0postgresql', 'text', '\u2603', 7].map(identifier => ({
        childConnections: [{ name: 'desktop-a', identifier }]
    }))]) {
    test(`malformed lookup result stays blocked: ${JSON.stringify(tree)}`, async () => {
        const t = tab({ 'wrdp-target': 'desktop-a' });
        t.tree(tree);
        await blocked(t);
        assert.equal(t.events.filter(e => e[0] === 'guacFatalPageError').length, 1);
        assert.equal(t.defaults, 0);
    });
}

test('encoding exception is caught by terminal failure handler', async () => {
    const t = tab({ 'wrdp-target': 'desktop-a' });
    t.encodingFails();
    await blocked(t);
    assert.equal(t.events.filter(e => e[0] === 'guacFatalPageError').length, 1);
    assert.equal(t.defaults, 0);
});

test('target enum renders escaped aliases without dynamic translation keys', async () => {
    const t = tab();
    const container = { childNodes: [] };
    const scope = { namespace: 'LOGIN', field: { name: 'wrdp-target',
        options: ['desktop-b', 'desktop-a', '<img onerror=attack>', 'desktop-a\n'] } };
    await t.form(container, 'ENUM', scope);
    assert.deepEqual(Array.from(scope.portalTargetOptions), ['desktop-b', 'desktop-a']);
    assert.match(container.innerHTML, /ng-options="option as option for option in portalTargetOptions"/);
    assert.doesNotMatch(container.innerHTML, /translate|attack/);
    assert.equal(t.compiled.length, 1);
    assert.equal(t.form(container, 'ENUM', { namespace: 'LOGIN', field: { name: 'other' } }), 'native-form');
    assert.equal(t.form(container, 'TEXT', scope), 'native-form');
    const translations = JSON.parse(fs.readFileSync(path.join(__dirname, 'translations/en.json'), 'utf8'));
    assert.equal(translations.LOGIN.FIELD_HEADER_WRDP_TARGET, 'Server');
});

test('target field shows the explicit validated URL selection and keeps an existing choice', async () => {
    const t = tab({ 'wrdp-target': 'desktop-a' });
    const classes = [];
    const container = { childNodes: [], closest: selector => {
        assert.equal(selector, '.labeled-field');
        return { classList: { add: name => classes.push(name) } };
    } };
    const scope = { namespace: 'LOGIN', field: { name: 'wrdp-target', options: ['desktop-a', 'desktop-b'] } };
    await t.form(container, 'ENUM', scope);
    assert.equal(scope.model, 'desktop-a');
    assert.deepEqual(classes, ['portal-target-labeled-field']);
    scope.model = 'desktop-b';
    await t.form(container, 'ENUM', scope);
    assert.equal(scope.model, 'desktop-b');
    const invalid = tab({ 'wrdp-target': '<untrusted>' });
    const empty = { namespace: 'LOGIN', field: scope.field };
    await invalid.form({ childNodes: [] }, 'ENUM', empty);
    assert.equal(empty.model, '');
});

for (const nativeURL of ['/client/saved-session', '/']) {
    test(`general landing never resumes native default ${nativeURL}`, async () => {
        const t = tab();
        t.native(Promise.resolve({ url: nativeURL }));
        await t.pending({ token: 'synthetic-existing-token' });
        assert.equal((await t.home()).url, '/');
        assert.equal(t.defaults, 1);
        assert.equal(t.lookups.length, 0);
    });
}

test('mixed catalog resolves each of three aliases through current native client identifiers', async () => {
    const connections = [
        { name: 'desktop-a', identifier: '17' },
        { name: 'desktop-b', identifier: '92' },
        { name: 'terminal-c', identifier: '93' }
    ];
    for (const connection of connections) {
        const t = tab({ 'wrdp-target': connection.name }, connections);
        await t.pending({ username: 'synthetic' });
        await t.pending({ 'totp-code': '000000' });
        const id = t.decode(await t.home());
        assert.equal(id.id, connection.identifier);
        assert.equal(id.dataSource, 'postgresql');
        assert.equal(id.type, 'c');
        assert.equal(t.defaults, 0);
    }
});
