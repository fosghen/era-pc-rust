'use strict';
// Node-only mocks: no Frida runtime, target process, Windows API or device.
const assert = require('node:assert/strict');
const {startObserver, decodeArguments, decodeWaitArray, pointerText, callerAttribution, OBSERVED_APIS} = require('./native_api_observer.js');

class Pointer {
    constructor(value, size = 4, memory = new Map(), reads = []) {
        this.size = size;
        this.value = BigInt.asUintN(size * 8, BigInt(value));
        this.memory = memory;
        this.reads = reads;
    }
    toString() { return '0x' + this.value.toString(16); }
    toUInt32() { return Number(BigInt.asUintN(32, this.value)); }
    isNull() { return this.value === 0n; }
    add(offset) { return new Pointer(this.value + BigInt(offset), this.size, this.memory, this.reads); }
    sub(other) { return new Pointer(this.value - other.value, this.size, this.memory, this.reads); }
    compare(other) { return this.value < other.value ? -1 : this.value > other.value ? 1 : 0; }
    readVolatile(size) {
        this.reads.push({address: this.toString(), size});
        const value = this.memory.get(this.toString());
        if (!value || value.byteLength !== size) throw new Error('PRIVATE PATH AND PAYLOAD MUST NOT LEAK');
        return value.slice(0);
    }
}

function args(values, size = 4, memory = new Map(), reads = []) {
    return values.map(value => new Pointer(value, size, memory, reads));
}
function handleBuffer(values, size) {
    const buffer = new ArrayBuffer(values.length * size);
    const view = new DataView(buffer);
    values.forEach((value, index) => {
        const number = BigInt(value);
        view.setUint32(index * size, Number(BigInt.asUintN(32, number)), true);
        if (size === 8) view.setUint32(index * size + 4, Number(number >> 32n), true);
    });
    return buffer;
}
function mockRuntime(options = {}) {
    const size = options.size || 4;
    const messages = [], callbacks = new Map(), exports = new Map(), detached = [];
    OBSERVED_APIS.forEach((name, index) => exports.set(name, 0x10000 + index * 0x100));
    for (const [name, value] of Object.entries(options.aliases || {})) exports.set(name, value);
    const runtime = {
        Process: {
            platform: 'windows', arch: size === 4 ? 'ia32' : 'x64', pointerSize: size,
            findModuleByAddress(address) {
                return options.findModule ? options.findModule(address) : null;
            },
            getModuleByName(name) {
                assert.equal(name, 'kernel32.dll');
                if (options.noModule) throw new Error('module unavailable');
                return {getExportByName(api) {
                    if ((options.missing || []).includes(api)) throw new Error('missing');
                    return new Pointer(exports.get(api), size);
                }};
            }
        },
        Interceptor: {attach(address, hooks) {
            if ((options.failAttach || []).includes(address.toString())) throw new Error('attach failure');
            assert.ok(!callbacks.has(address.toString()), 'one listener per unique address');
            callbacks.set(address.toString(), hooks);
            return {detach() { detached.push(address.toString()); }};
        }},
        send(payload) {
            // Serialization must never need NativePointer or binary attachments.
            messages.push(JSON.parse(JSON.stringify(payload)));
            if (options.onSend) options.onSend(payload);
            if (options.sendFails) throw new Error('channel closed');
        }
    };
    return {runtime, messages, callbacks, exports, detached,
        enter(api, values, threadId = 123, returnAddress = 0x12345678) {
            const context = {threadId, returnAddress: new Pointer(returnAddress, size), lastError: 7};
            const hooks = callbacks.get(new Pointer(exports.get(api), size).toString());
            const input = values.map(value => value instanceof Pointer ? value : new Pointer(value, size));
            hooks.onEnter.call(context, input);
            return {context, hooks, input};
        },
        leave(call, value = 1) { call.hooks.onLeave.call(call.context, new Pointer(value, size)); }
    };
}

let tests = 0;
function test(name, callback) {
    callback();
    tests++;
    console.log('ok - ' + name);
}

test('import is inert and configuration/platform are strict', () => {
    for (const config of [null, {}, {maxEvents: true}, {maxEvents: 0}, {maxEvents: 100001},
        {maxEvents: 1.1}, {maxEvents: '2'}, {maxEvents: 2, extra: 1}, []]) {
        assert.throws(() => startObserver(config, mockRuntime().runtime));
    }
    const fixture = mockRuntime();
    fixture.runtime.Process.platform = 'linux';
    assert.throws(() => startObserver({maxEvents: 2}, fixture.runtime));
    fixture.runtime.Process.platform = 'windows';
    fixture.runtime.Process.arch = 'arm64';
    assert.throws(() => startObserver({maxEvents: 2}, fixture.runtime));
    fixture.runtime.Process.arch = 'ia32';
    fixture.runtime.Process.pointerSize = 8;
    assert.throws(() => startObserver({maxEvents: 2}, fixture.runtime));
    assert.equal(fixture.callbacks.size, 0);
});

test('kernel32 failure precedes hooks; missing exports/attach failures reported', () => {
    const missingModule = mockRuntime({noModule: true});
    assert.throws(() => startObserver({maxEvents: 4}, missingModule.runtime));
    assert.equal(missingModule.callbacks.size, 0);
    const fixture = mockRuntime({missing: ['DeviceIoControl'], failAttach: ['0x10000']});
    const observer = startObserver({maxEvents: 4}, fixture.runtime);
    const ready = fixture.messages.find(message => message.type === 'ready');
    assert.equal(ready.arch, 'ia32');
    assert.equal(ready.platform, 'windows');
    assert.equal(ready.pointerSize, 4);
    assert.ok(ready.coveredApis.includes('WaitForMultipleObjects'));
    assert.ok(!ready.coveredApis.includes('DeviceIoControl'));
    assert.ok(!ready.coveredApis.includes('CreateEventA'));
    assert.equal(ready.coverage.completenessClaim, false);
    assert.equal(ready.coverage.requestedExportsCovered, false);
    assert.deepEqual(ready.coverage.missing, [{api: 'DeviceIoControl', reason: 'export_unavailable'},
        {api: 'CreateEventA', reason: 'attach_failed'}]);
    assert.throws(() => startObserver({maxEvents: 4}, fixture.runtime), /already started/);
    observer.stop();
    observer.stop();
    assert.equal(fixture.detached.length, OBSERVED_APIS.length - 2);
});

test('scalar APIs preserve DWORDs, BOOL raw values and pointer widths without reads', () => {
    const reads = [];
    const event = decodeArguments('CreateEventW', args([0, 2, 0xffffffff, 0x1234], 4, new Map(), reads), 4);
    assert.equal(event.manualResetRaw, 2);
    assert.equal(event.manualReset, true);
    assert.equal(event.initialStateRaw, 0xffffffff);
    assert.equal(event.namePointer, '0x1234');
    const thread = decodeArguments('CreateThread', args([0, 0x100000000n, 0x123456789abcdef0n, 7, 4, 8], 8), 8);
    assert.equal(thread.stackSizeHex, '0x100000000');
    assert.equal(thread.startAddress, '0x123456789abcdef0');
    assert.equal(thread.creationFlags, 4);
    for (const api of ['SetEvent', 'ResetEvent', 'ResumeThread', 'CloseHandle'])
        assert.deepEqual(decodeArguments(api, args([0x76000000]), 4), {handle: '0x76000000'});
    assert.deepEqual(decodeArguments('WaitForSingleObject', args([7, 0xffffffff]), 4),
        {handle: '0x7', timeoutMs: 0xffffffff});
    assert.deepEqual(reads, []);
});

test('CreateFile and DeviceIoControl expose pointers/scalars only, never buffers or strings', () => {
    const reads = [];
    for (const api of ['CreateFileA', 'CreateFileW']) {
        const fields = decodeArguments(api, args([0x1234, 0x80000000, 3, 0, 3, 0x80, 0], 4, new Map(), reads), 4);
        assert.equal(fields.fileNamePointer, '0x1234');
        assert.equal(fields.desiredAccess, 0x80000000);
        assert.equal(fields.creationDisposition, 3);
        assert.equal(Object.keys(fields).length, 7);
    }
    const fields = decodeArguments('DeviceIoControl', args([8, 0x222004, 0x1000, 400, 0x2000, 500, 0x3000, 0],
        4, new Map(), reads), 4);
    assert.deepEqual(fields, {device: '0x8', controlCode: 0x222004, inputPointer: '0x1000', inputSize: 400,
        outputPointer: '0x2000', outputSize: 500, bytesReturnedPointer: '0x3000', overlappedPointer: '0x0'});
    assert.deepEqual(reads, []);
});

test('wait arrays ia32/x64: bounded snapshot, order, duplicates and nonzero BOOL', () => {
    for (const size of [4, 8]) {
        for (const count of [1, 3, 64]) {
            const values = Array.from({length: count}, (_, index) => size === 4 ? BigInt(index % 2) : 0x1234567800000000n + BigInt(index % 2));
            const reads = [], memory = new Map([['0x2000', handleBuffer(values, size)]]);
            const fields = decodeArguments('WaitForMultipleObjects', args([count, 0x2000, 0xffffffff, 60000], size, memory, reads), size);
            assert.deepEqual(fields.array.handles, values.map(value => '0x' + value.toString(16)));
            assert.equal(fields.array.duplicateHandles, count > 2);
            assert.equal(fields.array.handlesValidated, false);
            assert.equal(fields.waitAllRaw, 0xffffffff);
            assert.equal(fields.waitAll, true);
            assert.deepEqual(reads, [{address: '0x2000', size: count * size}]);
        }
    }
});

test('wait array rejection does not return partial data or leak exception text', () => {
    const reads = [];
    for (const count of [0, 65, 0xffffffff]) {
        const result = decodeWaitArray(new Pointer(0x2000, 4, new Map(), reads), count, 4);
        assert.equal(result.error, 'count_outside_1_64');
        assert.equal(result.handles, null);
    }
    assert.equal(reads.length, 0);
    for (const size of [4, 8]) {
        const overflow = new Pointer(size === 4 ? 0xfffffffen : 0xfffffffffffffffen, size);
        assert.equal(decodeWaitArray(overflow, 2, size).error, 'address_overflow');
        assert.equal(decodeWaitArray(new Pointer(0, size), 1, size).error, 'array_unreadable');
        const result = decodeWaitArray(new Pointer(0x2000, size), 2, size);
        assert.equal(result.error, 'array_unreadable');
        assert.equal(result.handles, null);
        assert.ok(!JSON.stringify(result).includes('PRIVATE'));
    }
});

test('entry/leave call pairing survives nested concurrent order and preserves arguments', () => {
    const fixture = mockRuntime({size: 8});
    const observer = startObserver({maxEvents: 10}, fixture.runtime);
    const first = fixture.enter('CreateEventA', [0, 1, 0, 0], 11, 0x123456789abcdef0n);
    const second = fixture.enter('ResumeThread', [0x123456789000n], 12);
    fixture.leave(second, 0xffffffff);
    fixture.leave(first, 0x1234567800000001n);
    fixture.leave(first, 0); // Duplicate callback cannot duplicate an observation.
    const api = fixture.messages.filter(message => message.type === 'api');
    assert.deepEqual(api.map(item => [item.callId, item.phase, item.threadId]),
        [[1, 'enter', 11], [2, 'enter', 12], [2, 'leave', 12], [1, 'leave', 11]]);
    assert.equal(api[3].fields.returnValue, '0x1234567800000001');
    assert.equal(api[3].fields.returnU32, 1);
    assert.equal(api[3].returnAddress, '0x123456789abcdef0');
    assert.equal(first.input[1].toUInt32(), 1);
    assert.equal(first.context.lastError, 7);
    assert.equal(observer.stats().pendingCalls, 0);
    assert.equal(observer.stats().emittedApiEvents, 4);
    fixture.messages.forEach((message, index) => assert.equal(message.seq, index + 1));
});

test('pair reservation enforces cap with pending calls, odd budgets and one marker', () => {
    for (const maximum of [1, 2, 3, 4]) {
        const fixture = mockRuntime();
        const observer = startObserver({maxEvents: maximum}, fixture.runtime);
        const calls = Array.from({length: 5}, () => fixture.enter('SetEvent', [1]));
        for (const call of calls.reverse()) fixture.leave(call);
        for (let index = 0; index < 10; index++) fixture.leave(fixture.enter('CloseHandle', [2]));
        const api = fixture.messages.filter(message => message.type === 'api');
        assert.equal(api.length, Math.floor(maximum / 2) * 2);
        assert.equal(fixture.messages.filter(message => message.type === 'limit').length, 1);
        assert.equal(observer.stats().pendingCalls, 0);
        assert.equal(observer.stats().droppedCalls, 15 - Math.floor(maximum / 2));
        assert.ok(observer.stats().pairedSlotsReserved <= maximum);
    }
});

test('pending calls bounded independently and dropped calls do not decode arguments', () => {
    const fixture = mockRuntime();
    const observer = startObserver({maxEvents: 100000}, fixture.runtime);
    const calls = Array.from({length: 1024}, () => fixture.enter('SetEvent', [1]));
    const skipped = fixture.enter('SetEvent', []); // Invalid arguments must not be touched after cap.
    assert.equal(skipped.context.eraObservation, null);
    assert.equal(observer.stats().pendingCalls, 1024);
    assert.equal(observer.stats().droppedCalls, 1);
    assert.equal(fixture.messages.at(-1).reason, 'pending_call_limit');
    for (const call of calls) fixture.leave(call);
    fixture.leave(skipped);
    assert.equal(observer.stats().pendingCalls, 0);
});

test('deduplicated aliases and ambiguous signatures never guess argument layout', () => {
    const fixture = mockRuntime({aliases: {CreateEventW: 0x10000, DeviceIoControl: 0x10000}});
    startObserver({maxEvents: 4}, fixture.runtime);
    assert.equal(fixture.callbacks.size, OBSERVED_APIS.length - 2);
    const call = fixture.enter('CreateEventA', []);
    fixture.leave(call, 7);
    const entry = fixture.messages.find(message => message.type === 'api' && message.phase === 'enter');
    assert.deepEqual(entry.aliases, ['CreateEventA', 'CreateEventW', 'DeviceIoControl']);
    assert.equal(entry.ambiguousAliases, true);
    assert.equal(entry.fields.error, 'aliased_address_has_ambiguous_argument_schemas');
    const compatible = mockRuntime({aliases: {CreateEventW: 0x10000}});
    startObserver({maxEvents: 2}, compatible.runtime);
    compatible.leave(compatible.enter('CreateEventW', [0, 2, 0, 0]));
    const compatibleEntry = compatible.messages.find(message => message.type === 'api');
    assert.equal(compatibleEntry.ambiguousAliases, false);
    assert.equal(compatibleEntry.fields.manualResetRaw, 2);
});

test('decode/send errors stay bounded and redacted; stop detaches without changing target', () => {
    const fixture = mockRuntime({sendFails: true});
    const observer = startObserver({maxEvents: 4}, fixture.runtime);
    const call = fixture.enter('CreateFileW', []);
    fixture.leave(call);
    assert.equal(fixture.messages.find(message => message.type === 'api').fields.error, 'argument_metadata_unavailable');
    assert.ok(observer.stats().sendErrors > 0);
    assert.ok(!JSON.stringify(fixture.messages).includes('PRIVATE'));
    observer.stop();
    assert.equal(observer.stats().stopped, true);
    const count = fixture.messages.length;
    fixture.leave(fixture.enter('SetEvent', [1]));
    assert.equal(fixture.messages.length, count);
    assert.throws(() => pointerText({toString() { return 'PRIVATE/path'; }}, 4));
});

test('reentrant callbacks are suppressed and capped wait calls never read arrays', () => {
    let fixture, nested;
    fixture = mockRuntime({onSend(message) {
        if (message.type === 'api' && message.phase === 'enter')
            nested = fixture.enter('SetEvent', [9]);
    }});
    const observer = startObserver({maxEvents: 2}, fixture.runtime);
    const first = fixture.enter('SetEvent', [1]);
    assert.equal(observer.stats().suppressedReentrantCalls, 1);
    fixture.leave(nested);
    const reads = [];
    fixture.leave(fixture.enter('WaitForMultipleObjects', [3, new Pointer(0x2000, 4, new Map(), reads), 0, 1]));
    assert.deepEqual(reads, []);
    fixture.leave(first);
    assert.equal(observer.stats().emittedApiEvents, 2);
    assert.equal(observer.stats().pendingCalls, 0);
});

test('zero coverage is explicitly unusable and short arrays remain unavailable', () => {
    const fixture = mockRuntime({missing: OBSERVED_APIS});
    startObserver({maxEvents: 2}, fixture.runtime);
    const ready = fixture.messages.find(message => message.type === 'ready');
    assert.equal(ready.usable, false);
    assert.deepEqual(ready.coveredApis, []);
    assert.equal(ready.coverage.missing.length, OBSERVED_APIS.length);
    const pointer = new Pointer(0x2000);
    pointer.readVolatile = () => new ArrayBuffer(3);
    const result = decodeWaitArray(pointer, 1, 4);
    assert.equal(result.error, 'array_unreadable');
    assert.equal(result.handles, null);
});

test('caller attribution keeps only bounded basename/base/RVA, preserving x64 precision', () => {
    for (const size of [4, 8]) {
        const base = new Pointer(size === 4 ? 0x75000000n : 0x1234567800000000n, size);
        const module = {name: 'C:\\PRIVATE\\parent/fixture.dll', base, size: 0x10000,
            get path() { assert.fail('Module.path must never be accessed'); }};
        const process = {findModuleByAddress() { return module; }};
        const result = callerAttribution(base.add(0x968e), process, size);
        assert.deepEqual(result, {callerModuleStatus: 'resolved',
            callerModule: {name: 'fixture.dll', base: base.toString(), rva: '0x968e'}});
        assert.ok(!JSON.stringify(result).includes('PRIVATE'));
        assert.deepEqual(base.reads, []);
        assert.equal(callerAttribution(base, process, size).callerModule.rva, '0x0');
        assert.equal(callerAttribution(base.add(0xffff), process, size).callerModule.rva, '0xffff');
    }
});

test('caller lookup failures and invalid names/ranges are bounded and redacted', () => {
    const address = new Pointer(0x7500968e);
    assert.deepEqual(callerAttribution(address, {findModuleByAddress() { return null; }}, 4),
        {callerModule: null, callerModuleStatus: 'not_mapped'});
    assert.deepEqual(callerAttribution(address, {findModuleByAddress() { throw new Error('PRIVATE'); }}, 4),
        {callerModule: null, callerModuleStatus: 'lookup_failed'});
    for (const name of ['', '.', '..', 'bad\nname.dll', 'x'.repeat(129), 'x'.repeat(32769), null]) {
        const module = {name, base: new Pointer(0x75000000), size: 0x10000};
        const result = callerAttribution(address, {findModuleByAddress() { return module; }}, 4);
        assert.equal(result.callerModule, null);
        assert.equal(result.callerModuleStatus, 'invalid_module_name');
    }
    for (const [base, size] of [[0x75010000, 0x10000], [0x75000000, 0x968e],
        [0xfffffff0, 32], [0x75000000, 0], [0x75000000, -1], [0x75000000, 0x100000000],
        [0x75000000, NaN], [0x75000000, true]]) {
        const module = {name: 'fixture.dll', base: new Pointer(base), size};
        const result = callerAttribution(address, {findModuleByAddress() { return module; }}, 4);
        assert.equal(result.callerModule, null);
        assert.equal(result.callerModuleStatus, 'invalid_module_range');
    }
    const module = {name: 'x'.repeat(128), base: new Pointer(0x75000000), size: 0x10000};
    assert.equal(callerAttribution(address, {findModuleByAddress() { return module; }}, 4).callerModule.name.length, 128);
});

test('caller attribution snapshot is reused on leave, refreshed on next entry, and skipped after cap', () => {
    let calls = 0;
    const module = {name: 'first.dll', base: new Pointer(0x12340000), size: 0x10000};
    const fixture = mockRuntime({findModule() { calls++; return module; }});
    startObserver({maxEvents: 4}, fixture.runtime);
    const first = fixture.enter('SetEvent', [1]);
    module.name = 'second.dll';
    const second = fixture.enter('SetEvent', [2]);
    module.name = 'third.dll';
    fixture.leave(second);
    fixture.leave(first);
    fixture.leave(fixture.enter('SetEvent', [3]));
    const events = fixture.messages.filter(message => message.type === 'api');
    assert.deepEqual(events.map(event => event.callerModule.name), ['first.dll', 'second.dll', 'second.dll', 'first.dll']);
    assert.equal(calls, 2);
    assert.ok(events.every(event => event.callerModuleStatus === 'resolved'));
    assert.ok(events.every(event => event.callerModule.rva === '0x5678'));
});

test('caller lookup failure does not suppress API argument or return observations', () => {
    const fixture = mockRuntime({findModule() { throw new Error('PRIVATE caller path'); }});
    startObserver({maxEvents: 2}, fixture.runtime);
    fixture.leave(fixture.enter('SetEvent', [0x76000004]), 1);
    const events = fixture.messages.filter(message => message.type === 'api');
    assert.deepEqual(events.map(event => event.callerModuleStatus), ['lookup_failed', 'lookup_failed']);
    assert.ok(events.every(event => event.callerModule === null));
    assert.equal(events[0].fields.handle, '0x76000004');
    assert.equal(events[1].fields.returnU32, 1);
    assert.ok(!JSON.stringify(events).includes('PRIVATE'));
});

console.log(`${tests} native observer mock tests passed`);
