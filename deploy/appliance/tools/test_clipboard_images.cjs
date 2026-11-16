/* Licensed under the Apache License, Version 2.0. See LICENSE. */
'use strict';
// Real source modules, controlled browser/transport boundaries; no credentials.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../../..');
const frontend = path.join(root, 'guacamole/src/main/frontend/src/app');
const registry = {};
const timers = new Map();
let timerSequence = 0;
let clock = 0;
const q = {
    resolve: value => Promise.resolve(value),
    defer() {
        let resolve, reject;
        const promise = new Promise((yes, no) => {resolve = yes; reject = no;});
        return {resolve, reject, promise};
    }
};
const element = () => ({className: '', value: '', addEventListener() {},
    blur() {}, focus() {}, appendChild() {}});
const document = {createElement: element, body: element()};
const window = {document, setTimeout(fn, delay) {const id = ++timerSequence; timers.set(id, {fn, due: clock + delay}); return id;},
    clearTimeout(id) {timers.delete(id);}};
const advance = milliseconds => {
    clock += milliseconds;
    for (const [id, timer] of Array.from(timers)) {
        if (timer.due <= clock) {timers.delete(id); timer.fn();}
    }
};
const navigator = {};
const services = {$q: q, $window: window, $rootScope: {$broadcast() {}},
    sessionStorageFactory: {create(initial) {let value = initial;
        return replacement => replacement === undefined ? value : (value = replacement);}}};
const writers = [];
const Guacamole = {
    StringWriter: function(stream) {this.sendText = text => stream.events.push(['text', text]);
        this.sendEnd = () => stream.events.push(['end']);},
    BlobWriter: function(stream) {writers.push(this);
        this.sendBlob = data => stream.events.push(['blob', data]);
        this.sendEnd = () => stream.events.push(['end']);}
};
const context = vm.createContext({Blob, navigator, URL, Guacamole, document,
    angular: {noop() {}, module() {return {
        factory(name, definition) {registry[name] = definition.at(-1);},
        directive(name, definition) {registry[name] = definition.at(-1);}
    };}},
    console, setTimeout, clearTimeout});
function load(file) {vm.runInContext(fs.readFileSync(path.join(frontend, file), 'utf8'), context);}
const injector = {get(name) {return services[name] || function SyntheticType() {};}};
load('clipboard/types/ClipboardData.js');
services.ClipboardData = registry.ClipboardData();
load('clipboard/services/clipboardService.js');
services.clipboardService = registry.clipboardService(injector);
load('client/types/ManagedClient.js');
const ManagedClient = registry.ManagedClient(services.$rootScope, injector);
const service = services.clipboardService;
const png = new Blob([Uint8Array.of(137, 80, 78, 71, 0, 255)], {type: 'image/png'});
const item = (type, data) => ({types: [type], getType: async requested => {
    assert.equal(requested, type); return data;
}});
const tick = () => new Promise(resolve => setImmediate(resolve));
(async () => {
    navigator.clipboard = {read: async () => [item('text/plain', new Blob(['caption'])), item('image/png', png)]};
    let value = await service.getClipboard();
    assert.equal(value.type, 'image/png');
    assert.deepEqual(Buffer.from(await value.data.arrayBuffer()), Buffer.from(await png.arrayBuffer()));
    navigator.clipboard.read = async () => [item('text/plain', new Blob(['hello \u044f']))];
    value = await service.getClipboard();
    assert.equal(value.type, 'text/plain'); assert.equal(value.data, 'hello \u044f');
    let copied = 0;
    document.execCommand = () => {copied++; throw new Error('Unexpected local clipboard write');};
    navigator.clipboard.read = async () => [item('image/png', png)];
    await service.resyncClipboard();
    assert.equal(copied, 0);
    navigator.clipboard.read = async () => {throw new Error('denied');};
    assert.equal((await service.getClipboard()).type, 'image/png');
    navigator.clipboard.read = async () => [item('text/html', new Blob(['<img src="https://invalid.example/">']))];
    assert.equal((await service.getClipboard()).type, 'image/png');
    navigator.clipboard = {readText: async () => 'legacy'};
    assert.equal((await service.getClipboard()).data, 'legacy');
    const events = [];
    const client = {id: 'fixture', protocol:'rdp', client: {createClipboardStream(type) {events.push(['stream', type]); return {events};}}};
    for (const protocol of ['ssh', undefined]) {
        const unsupported = {...client, protocol};
        assert.equal(await ManagedClient.setClipboard(unsupported, {type:'image/png',data:png}), false);
        assert.equal(events.length, 0);
    }
    let settled = false;
    const sent = ManagedClient.setClipboard(client, {type: 'image/png', data: png}).then(result => {settled = true; return result;});
    await tick(); assert.equal(settled, false);
    assert.deepEqual(events.map(event => event[0]), ['stream', 'blob']);
    writers.at(-1).oncomplete();
    assert.equal(await sent, true);
    assert.deepEqual(events.map(event => event[0]), ['stream', 'blob', 'end']);
    assert.equal(timers.size, 0);
    const failed = ManagedClient.setClipboard(client, {type: 'image/png', data: png});
    await tick();
    writers.at(-1).onack({isError: () => true});
    assert.equal(await failed, false); assert.equal(timers.size, 0);
    const expired = ManagedClient.setClipboard(client, {type: 'image/png', data: png});
    await tick();
    advance(15000);
    assert.equal(await expired, false); assert.equal(timers.size, 0);
    writers.at(-1).onack({isError: () => false});
    assert.equal(timers.size, 0);
    let slowSettled = false;
    const slow = ManagedClient.setClipboard(client, {type: 'image/png', data: png})
        .then(value => {slowSettled = true; return value;});
    await tick();
    advance(14000); await tick(); assert.equal(slowSettled, false);
    writers.at(-1).onack({isError: () => false});
    advance(14000); await tick(); assert.equal(slowSettled, false);
    writers.at(-1).oncomplete(); assert.equal(await slow, true);
    assert.equal(await ManagedClient.setClipboard(client, {type: 'text/plain', data: 'ordinary'}), true);
    assert.deepEqual(events.slice(-3).map(event => event[0]), ['stream', 'text', 'end']);

    const beforeOverlap = events.length;
    const initialSync = ManagedClient.setClipboard(client, {type: 'image/png', data: png});
    const focusSync = ManagedClient.setClipboard(client, {type: 'text/plain', data: 'second'});
    await tick();
    assert.deepEqual(events.slice(beforeOverlap).map(event => event[0]), ['stream', 'blob']);
    writers.at(-1).oncomplete();
    assert.equal(await initialSync, true); assert.equal(await focusSync, true);
    assert.deepEqual(events.slice(beforeOverlap).map(event => event[0]), ['stream', 'blob', 'end', 'stream', 'text', 'end']);

    const oldNative = client.client;
    const beforeReplacement = events.length;
    const activeWrite = ManagedClient.setClipboard(client, {type: 'image/png', data: png});
    const queuedWrite = ManagedClient.setClipboard(client, {type: 'image/png', data: png});
    await tick();
    client.client = {...oldNative};
    writers.at(-1).oncomplete();
    assert.equal(await activeWrite, true); assert.equal(await queuedWrite, false);
    assert.deepEqual(events.slice(beforeReplacement).map(event => event[0]), ['stream', 'blob', 'end']);
    client.client = oldNative;

    // Instantiate the actual directive with inert display boundaries and verify
    // that rapid keyup events cannot overtake the asynchronous image stream.
    const listeners = {}, watches = {}, domListeners = {};
    services.ManagedClient = ManagedClient;
    services.$rootScope.$on = () => {};
    window.addEventListener = (name, fn) => {domListeners[name] = fn;};
    window.removeEventListener = (name, fn) => {if (domListeners[name] === fn) delete domListeners[name];};
    const device = function() {this.on = this.onEach = this.offEach = () => {};};
    Guacamole.Mouse = device; Guacamole.Touch = device;
    Guacamole.Mouse.Touchscreen = device; Guacamole.Mouse.Touchpad = device;
    Guacamole.Keyboard = {Keysym: {CTRL_L: 0xFFE3}};
    const main = {...element(), contains: () => false, offsetWidth: 0, offsetHeight: 0};
    const keys = [];
    client.client.getDisplay = () => ({scale() {}, getElement: element});
    client.client.sendKeyEvent = (state, key) => keys.push([state, key]);
    client.clientProperties = {focused: true, scale: 1};
    const scope = {client, $on(name, fn) {listeners[name] = fn;},
        $watch(name, fn) {watches[name] = fn;}, $watchGroup() {}, $evalAsync() {}};
    load('client/directives/guacClient.js');
    registry.guacClient().controller.at(-1)(scope, injector, {0: main, find: () => [element()]});
    watches.client(client);
    navigator.clipboard = {read: async () => [item('image/png', png)]};
    const event = {preventDefault() {}};
    listeners.guacKeydown(event, 118, {modifiers: {ctrl: true}});
    listeners.guacKeyup(event, 118);
    listeners.guacKeyup(event, 0xFFE3);
    await tick(); assert.deepEqual(keys, []);
    writers.at(-1).oncomplete(); await tick();
    assert.deepEqual(keys, [[1, 118], [0, 118], [0, 0xFFE3]]);
    keys.length = 0;
    let prevented = false;
    domListeners.paste({target: document.body, preventDefault() {prevented = true;},
        clipboardData: {items: [{kind: 'file', type: 'image/png', getAsFile: () => png}]}});
    await tick(); assert.equal(prevented, true); assert.deepEqual(keys, []);
    writers.at(-1).oncomplete(); await tick();
    assert.deepEqual(keys, [[1, 0xFFE3], [1, 118], [0, 118], [0, 0xFFE3]]);
    keys.length = 0;
    listeners.guacKeydown(event, 118, {modifiers: {ctrl: true}});
    await tick();
    const pendingWriter = writers.at(-1);
    scope.client = {...client, id: 'replacement', client: {...client.client}};
    watches.client(scope.client);
    pendingWriter.oncomplete(); await tick(); assert.deepEqual(keys, []);
    listeners.$destroy(); assert.equal(domListeners.paste, undefined);
    console.log(JSON.stringify({pngExact: true, pngPreferred: true, text: true,
        deniedPreservesClipboard: true, noHtmlFetch: true, legacy: true,
        waitsForBlobCompletion: true, ackFailure: true, finiteFailure: true,
        keyOrder: true, contextPaste: true, noCrossClientPaste: true, listenerCleanup: true,
        readSyncPreservesLocalClipboard: true, progressExtendsTimeout: true,
        serializedWrites: true, queuedOldClientRefused: true}));
})().catch(error => {console.error(error); process.exitCode = 1;});
