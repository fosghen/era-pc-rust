/* Read-only API metadata observer, Frida 17 JavaScript API.
 * Primary API documentation: https://frida.re/docs/javascript-api/
 * Interceptor instrumentation has timing/coverage effects; this is not a claim
 * of transparent or complete observation. No target data/result modification.
 * The ONLY target-memory read is a bounded WaitForMultipleObjects handle array.
 * Bootstrap explicitly with startObserver({maxEvents: N}); Node import is inert.
 */
'use strict';

const OBSERVED_APIS = Object.freeze([
    'CreateEventA', 'CreateEventW', 'SetEvent', 'ResetEvent', 'CreateThread',
    'ResumeThread', 'WaitForSingleObject', 'WaitForMultipleObjects', 'CloseHandle',
    'CreateFileA', 'CreateFileW', 'DeviceIoControl'
]);
const ACTIVE_RUNTIMES = new WeakSet();

function pointerText(value, pointerSize) {
    const text = value.toString();
    if (typeof text !== 'string' || !/^0x[0-9a-f]+$/i.test(text) || text.length > 2 + pointerSize * 2)
        throw new Error('Invalid pointer representation');
    return '0x' + text.slice(2).replace(/^0+(?=.)/, '').toLowerCase();
}

function u32(value) {
    const number = value.toUInt32();
    if (!Number.isInteger(number) || number < 0 || number > 0xffffffff)
        throw new Error('Invalid DWORD representation');
    return number;
}

function callerAttribution(returnAddress, process, pointerSize) {
    const unavailable = status => ({callerModule: null, callerModuleStatus: status});
    let found;
    try {
        pointerText(returnAddress, pointerSize);
        found = process.findModuleByAddress(returnAddress);
    } catch (_) { return unavailable('lookup_failed'); }
    if (found === null || found === undefined) return unavailable('not_mapped');
    try {
        // Module.name is canonical metadata, not a target-memory string read.
        // Never access Module.path, symbol tables or code/data bytes.
        const rawName = found.name;
        if (typeof rawName !== 'string' || rawName.length > 32768)
            return unavailable('invalid_module_name');
        const separator = Math.max(rawName.lastIndexOf('/'), rawName.lastIndexOf('\\'));
        const name = rawName.slice(separator + 1);
        if (!name || name.length > 128 || name === '.' || name === '..' || /[\x00-\x1f\x7f]/.test(name))
            return unavailable('invalid_module_name');
        const base = found.base, size = found.size;
        if (!Number.isSafeInteger(size) || size <= 0 || size > 0xffffffff)
            return unavailable('invalid_module_range');
        const baseText = pointerText(base, pointerSize);
        const last = base.add(size - 1);
        if (last.compare(base) < 0 || returnAddress.compare(base) < 0 || returnAddress.compare(last) > 0)
            return unavailable('invalid_module_range');
        return {callerModule: {name, base: baseText, rva: pointerText(returnAddress.sub(base), pointerSize)},
            callerModuleStatus: 'resolved'};
    } catch (_) { return unavailable('invalid_module_metadata'); }
}

function decodeWaitArray(pointer, count, pointerSize) {
    const result = {handles: null, duplicateHandles: null, handlesValidated: false,
        limit: 64, scope: 'Raw handle-array snapshot only; not Windows object validation'};
    if (!Number.isInteger(count) || count < 1 || count > 64) {
        result.error = 'count_outside_1_64';
        return result;
    }
    if (pointerSize !== 4 && pointerSize !== 8) throw new Error('Unsupported pointer size');
    try {
        if (pointer.isNull()) throw new Error('null');
        const length = count * pointerSize;
        if (pointer.add(length - 1).compare(pointer) < 0) {
            result.error = 'address_overflow';
            return result;
        }
        // Volatile read avoids native access exceptions when concurrent target
        // threads invalidate memory. This is not an atomic synchronization read.
        const buffer = pointer.readVolatile(length);
        if (!(buffer instanceof ArrayBuffer) || buffer.byteLength !== length)
            throw new Error('short snapshot');
        const view = new DataView(buffer);
        const handles = [];
        for (let index = 0; index < count; index++) {
            const low = view.getUint32(index * pointerSize, true);
            const high = pointerSize === 8 ? view.getUint32(index * pointerSize + 4, true) : 0;
            handles.push('0x' + (high ? high.toString(16) + low.toString(16).padStart(8, '0') : low.toString(16)));
        }
        result.handles = handles;
        result.duplicateHandles = new Set(handles).size !== handles.length;
    } catch (_) {
        result.error = 'array_unreadable';
    }
    return result;
}

function schemaFor(api) {
    if (api === 'CreateEventA' || api === 'CreateEventW') return 'event_create';
    if (api === 'CreateFileA' || api === 'CreateFileW') return 'file_create';
    if (['SetEvent', 'ResetEvent', 'ResumeThread', 'CloseHandle'].includes(api)) return 'handle_only';
    return api;
}

function decodeArguments(api, args, pointerSize) {
    const p = index => pointerText(args[index], pointerSize);
    const n = index => u32(args[index]);
    switch (schemaFor(api)) {
    case 'event_create': {
        const manualReset = n(1), initialState = n(2);
        return {securityAttributes: p(0), manualResetRaw: manualReset, manualReset: manualReset !== 0,
            initialStateRaw: initialState, initialState: initialState !== 0, namePointer: p(3)};
    }
    case 'handle_only':
        return {handle: p(0)};
    case 'CreateThread':
        return {securityAttributes: p(0), stackSizeHex: p(1), startAddress: p(2), parameter: p(3),
            creationFlags: n(4), threadIdPointer: p(5)};
    case 'WaitForSingleObject':
        return {handle: p(0), timeoutMs: n(1)};
    case 'WaitForMultipleObjects': {
        const count = n(0), waitAll = n(2);
        return {countRaw: count, arrayPointer: p(1), waitAllRaw: waitAll, waitAll: waitAll !== 0,
            timeoutMs: n(3), array: decodeWaitArray(args[1], count, pointerSize)};
    }
    case 'file_create':
        return {fileNamePointer: p(0), desiredAccess: n(1), shareMode: n(2), securityAttributes: p(3),
            creationDisposition: n(4), flagsAndAttributes: n(5), templateFile: p(6)};
    case 'DeviceIoControl':
        return {device: p(0), controlCode: n(1), inputPointer: p(2), inputSize: n(3),
            outputPointer: p(4), outputSize: n(5), bytesReturnedPointer: p(6), overlappedPointer: p(7)};
    default:
        throw new Error('Unsupported argument schema');
    }
}

function startObserver(config, runtime = globalThis) {
    if (!config || typeof config !== 'object' || Array.isArray(config) ||
            Object.keys(config).some(key => key !== 'maxEvents') ||
            !Number.isInteger(config.maxEvents) || config.maxEvents < 1 || config.maxEvents > 100000)
        throw new Error('Configuration must contain only maxEvents integer 1..100000');
    const process = runtime.Process;
    if (!process || process.platform !== 'windows' || !['ia32', 'x64'].includes(process.arch) ||
            process.pointerSize !== (process.arch === 'ia32' ? 4 : 8))
        throw new Error('Only Windows ia32/x64 are supported');
    if (ACTIVE_RUNTIMES.has(runtime)) throw new Error('Observer already started for this runtime');
    // Mandatory module lookup fails before installing any listeners.
    const kernel32 = process.getModuleByName('kernel32.dll');
    const maxEvents = config.maxEvents, pointerSize = process.pointerSize;
    const maxPending = Math.min(1024, Math.floor(maxEvents / 2));
    const counters = {emittedApiEvents: 0, acceptedCalls: 0, pendingCalls: 0, droppedCalls: 0,
        suppressedReentrantCalls: 0, sendErrors: 0};
    let sequence = 0, limitSent = false, stopped = false, inCallback = false;
    const listeners = [], groups = new Map(), missing = [], attached = [];
    const increment = key => { counters[key] = Math.min(Number.MAX_SAFE_INTEGER, counters[key] + 1); };
    function emit(payload) {
        try { runtime.send(Object.assign({seq: ++sequence}, payload)); }
        catch (_) { increment('sendErrors'); }
    }
    function limit(reason) {
        if (!limitSent) {
            limitSent = true;
            emit({type: 'limit', reason, maxEvents, maxPending,
                emittedApiEvents: counters.emittedApiEvents, pendingCalls: counters.pendingCalls,
                droppedCallsSnapshot: counters.droppedCalls,
                note: 'One marker only; final counters available through stats()'});
        }
    }
    ACTIVE_RUNTIMES.add(runtime);
    for (const api of OBSERVED_APIS) {
        try {
            const address = kernel32.getExportByName(api);
            if (address.isNull()) throw new Error('Null export address');
            const key = pointerText(address, pointerSize);
            if (!groups.has(key)) groups.set(key, {address, addressText: key, aliases: []});
            groups.get(key).aliases.push(api);
        } catch (_) { missing.push({api, reason: 'export_unavailable'}); }
    }
    for (const group of groups.values()) {
        const schema = new Set(group.aliases.map(schemaFor));
        const ambiguous = schema.size !== 1;
        const api = group.aliases[0];
        try {
            const listener = runtime.Interceptor.attach(group.address, {
                onEnter(args) {
                    this.eraObservation = null;
                    if (inCallback) { increment('suppressedReentrantCalls'); return; }
                    if (stopped) return;
                    inCallback = true;
                    try {
                        if (counters.emittedApiEvents + counters.pendingCalls + 2 > maxEvents) {
                            increment('droppedCalls'); limit('api_pair_budget'); return;
                        }
                        if (counters.pendingCalls >= maxPending) {
                            increment('droppedCalls'); limit('pending_call_limit'); return;
                        }
                        const call = {callId: ++counters.acceptedCalls, api, aliases: group.aliases,
                            threadId: this.threadId, returnAddress: null,
                            callerModule: null, callerModuleStatus: 'return_address_unavailable'};
                        this.eraObservation = call;
                        counters.pendingCalls++;
                        let fields;
                        try {
                            call.returnAddress = pointerText(this.returnAddress, pointerSize);
                            // Snapshot at entry, reused on leave even if mappings
                            // change. No address cache or module lifetime claims.
                            Object.assign(call, callerAttribution(this.returnAddress, process, pointerSize));
                            fields = ambiguous ? {error: 'aliased_address_has_ambiguous_argument_schemas'} :
                                decodeArguments(api, args, pointerSize);
                        } catch (_) { fields = {error: 'argument_metadata_unavailable'}; }
                        counters.emittedApiEvents++;
                        emit(Object.assign({type: 'api', phase: 'enter', address: group.addressText,
                            fields, ambiguousAliases: ambiguous}, call));
                    } finally { inCallback = false; }
                },
                onLeave(retval) {
                    const call = this.eraObservation;
                    this.eraObservation = null;
                    if (!call || stopped) return;
                    const previousCallback = inCallback;
                    inCallback = true;
                    try {
                        let fields;
                        try {
                            fields = {returnValue: pointerText(retval, pointerSize), returnU32: u32(retval)};
                            if (Number.isInteger(this.lastError)) fields.lastErrorSnapshot = this.lastError;
                        } catch (_) { fields = {error: 'return_metadata_unavailable'}; }
                        counters.pendingCalls--;
                        counters.emittedApiEvents++;
                        emit(Object.assign({type: 'api', phase: 'leave', address: group.addressText, fields}, call));
                        if (counters.emittedApiEvents === maxEvents) limit('api_event_budget');
                    } finally { inCallback = previousCallback; }
                }
            });
            listeners.push(listener);
            attached.push({address: group.addressText, aliases: group.aliases, ambiguousArgumentSchemas: ambiguous});
        } catch (_) {
            for (const name of group.aliases) missing.push({api: name, reason: 'attach_failed'});
        }
    }
    const coverage = {requested: OBSERVED_APIS.slice(), attached, missing,
        requestedExportsCovered: missing.length === 0,
        completenessClaim: false,
        limitations: 'Selected kernel32 exports only; aliases deduplicated by address; unhooked paths, ' +
            'inlined code, other processes and calls before setup are not observed; instrumentation affects timing'};
    emit({type: 'coverage', coverage});
    emit({type: 'ready', platform: 'windows', arch: process.arch, pointerSize, maxEvents, maxPending,
        coveredApis: attached.flatMap(group => group.aliases),
        coverage, usable: attached.length > 0, metadataOnly: true,
        callerAttribution: 'Entry-time module basename/base/RVA metadata; no paths or symbols; not call-intent attribution',
        reads: 'Only bounded wait handle arrays; no strings, file paths, IOCTL buffers or pointed-to output data'});
    return {
        stats() { return Object.assign({maxEvents, maxPending, limitMarkerSent: limitSent, stopped,
            pairedSlotsReserved: counters.emittedApiEvents + counters.pendingCalls}, counters); },
        stop() {
            if (stopped) return;
            stopped = true;
            for (const listener of listeners) {
                try { listener.detach(); } catch (_) { /* Unload may already have detached it. */ }
            }
            ACTIVE_RUNTIMES.delete(runtime);
        }
    };
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {startObserver, decodeArguments, decodeWaitArray, pointerText, callerAttribution, OBSERVED_APIS};
}
