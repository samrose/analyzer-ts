# TypeScript Codebase Analysis Report

## Overall Metrics
- Total TypeScript Files: 255
- Total Imports: 240
- Total Exports: 64
- Total Interfaces: 4026
- Total Classes: 188
- Total Functions: 1954

## Dependency Analysis

### analyzer.ts
- Imports: fs, path, typescript
- Exports: 
- Interfaces: FileAnalysis, CodebaseMetrics
- Classes: TypeScriptAnalyzer
- Functions: 

### cli.ts
- Imports: commander, path, fs, ./analyzer
- Exports: 
- Interfaces: 
- Classes: 
- Functions: main

### register-hook-require.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### register.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### source-map-support.d.ts
- Imports: 
- Exports: 
- Interfaces: RawSourceMap, UrlAndMap, Options, Position
- Classes: 
- Functions: wrapCallSite, getErrorSource, mapSourcePosition, retrieveSourceMap, resetRetrieveHandlers, install, uninstall

### resolve-uri.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: resolve

### scopes.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: decodeOriginalScopes, encodeOriginalScopes, decodeGeneratedRanges, encodeGeneratedRanges

### sourcemap-codec.d.ts
- Imports: 
- Exports: ./scopes, ./scopes
- Interfaces: 
- Classes: 
- Functions: decode, encode, encode

### strings.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: StringWriter, StringReader
- Functions: 

### vlq.d.ts
- Imports: ./strings
- Exports: 
- Interfaces: 
- Classes: 
- Functions: decodeInteger, encodeInteger, hasMoreVlq

### any-map.d.ts
- Imports: ./trace-mapping, ./types
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### binary-search.d.ts
- Imports: ./sourcemap-segment
- Exports: 
- Interfaces: 
- Classes: 
- Functions: binarySearch, upperBound, lowerBound, memoizedState, memoizedBinarySearch

### by-source.d.ts
- Imports: ./sourcemap-segment, ./binary-search
- Exports: 
- Interfaces: 
- Classes: 
- Functions: buildBySources

### resolve.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: resolve

### sort.d.ts
- Imports: ./sourcemap-segment
- Exports: 
- Interfaces: 
- Classes: 
- Functions: maybeSort

### sourcemap-segment.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### strip-filename.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: stripFilename

### trace-mapping.d.ts
- Imports: ./sourcemap-segment, ./types
- Exports: ./sourcemap-segment, ./types, ./any-map
- Interfaces: 
- Classes: TraceMap
- Functions: 

### types.d.ts
- Imports: ./sourcemap-segment, ./trace-mapping
- Exports: 
- Interfaces: SourceMapV3, EncodedSourceMap, DecodedSourceMap, Section, SectionedSourceMap
- Classes: SourceMap
- Functions: 

### strict.d.ts
- Imports: node:assert, node:assert
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### assert.d.ts
- Imports: 
- Exports: 
- Interfaces: CallTrackerCall, CallTrackerReportInformation
- Classes: AssertionError, CallTracker
- Functions: assert, fail, fail, ok, equal, notEqual, deepEqual, notDeepEqual, strictEqual, notStrictEqual, deepStrictEqual, notDeepStrictEqual, throws, throws, doesNotThrow, doesNotThrow, ifError, rejects, rejects, doesNotReject, doesNotReject, match, doesNotMatch

### async_hooks.d.ts
- Imports: 
- Exports: async_hooks
- Interfaces: HookCallbacks, AsyncHook, AsyncResourceOptions
- Classes: AsyncResource, AsyncLocalStorage
- Functions: executionAsyncId, executionAsyncResource, triggerAsyncId, createHook

### buffer.buffer.d.ts
- Imports: 
- Exports: 
- Interfaces: BufferConstructor, Buffer
- Classes: 
- Functions: 

### buffer.d.ts
- Imports: node:crypto, node:stream/web
- Exports: buffer
- Interfaces: BlobOptions, FileOptions, BufferConstructor, Buffer, Blob, File
- Classes: Blob, File
- Functions: isUtf8, isAscii, transcode, resolveObjectURL, atob, btoa

### child_process.d.ts
- Imports: node:fs, node:events, node:dgram, node:net, node:stream, node:url
- Exports: child_process
- Interfaces: ChildProcessWithoutNullStreams, ChildProcessByStdio, MessageOptions, MessagingOptions, ProcessEnvOptions, CommonOptions, CommonSpawnOptions, SpawnOptions, SpawnOptionsWithoutStdio, SpawnOptionsWithStdioTuple, ExecOptions, ExecOptionsWithStringEncoding, ExecOptionsWithBufferEncoding, ExecException, PromiseWithChild, ExecFileOptions, ExecFileOptionsWithStringEncoding, ExecFileOptionsWithBufferEncoding, ExecFileOptionsWithOtherEncoding, ForkOptions, SpawnSyncOptions, SpawnSyncOptionsWithStringEncoding, SpawnSyncOptionsWithBufferEncoding, SpawnSyncReturns, CommonExecOptions, ExecSyncOptions, ExecSyncOptionsWithStringEncoding, ExecSyncOptionsWithBufferEncoding, ExecFileSyncOptions, ExecFileSyncOptionsWithStringEncoding, ExecFileSyncOptionsWithBufferEncoding
- Classes: ChildProcess
- Functions: spawn, spawn, spawn, spawn, spawn, spawn, spawn, spawn, spawn, spawn, spawn, spawn, spawn, spawn, spawn, spawn, spawn, spawn, spawn, spawn, exec, exec, exec, exec, exec, exec, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, execFile, execFile, execFile, execFile, execFile, execFile, execFile, execFile, execFile, execFile, execFile, execFile, execFile, execFile, execFile, execFile, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, fork, fork, spawnSync, spawnSync, spawnSync, spawnSync, spawnSync, spawnSync, spawnSync, spawnSync, execSync, execSync, execSync, execSync, execFileSync, execFileSync, execFileSync, execFileSync, execFileSync, execFileSync, execFileSync, execFileSync

### cluster.d.ts
- Imports: node:child_process, node:net
- Exports: cluster, cluster
- Interfaces: ClusterSettings, Address, Cluster
- Classes: Worker
- Functions: 

### disposable.d.ts
- Imports: 
- Exports: 
- Interfaces: SymbolConstructor, Disposable, AsyncDisposable
- Classes: 
- Functions: 

### index.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### indexable.d.ts
- Imports: 
- Exports: 
- Interfaces: RelativeIndexable, String, Array, ReadonlyArray, Int8Array, Uint8Array, Uint8ClampedArray, Int16Array, Uint16Array, Int32Array, Uint32Array, Float32Array, Float64Array, BigInt64Array, BigUint64Array
- Classes: 
- Functions: 

### iterators.d.ts
- Imports: 
- Exports: 
- Interfaces: IteratorObject, AsyncIteratorObject, Iterator, AsyncIterator
- Classes: 
- Functions: 

### console.d.ts
- Imports: node:util
- Exports: 
- Interfaces: Console, ConsoleConstructorOptions, ConsoleConstructor
- Classes: 
- Functions: 

### constants.d.ts
- Imports: node:os, node:crypto, node:fs
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### crypto.d.ts
- Imports: node:stream, node:tls
- Exports: crypto
- Interfaces: HashOptions, KeyExportOptions, JwkKeyExportOptions, JsonWebKey, AsymmetricKeyDetails, CipherCCMOptions, CipherGCMOptions, CipherOCBOptions, CipherCCM, CipherGCM, CipherOCB, DecipherCCM, DecipherGCM, DecipherOCB, PrivateKeyInput, PublicKeyInput, JsonWebKeyInput, SigningOptions, SignPrivateKeyInput, SignKeyObjectInput, SignJsonWebKeyInput, VerifyPublicKeyInput, VerifyKeyObjectInput, VerifyJsonWebKeyInput, DiffieHellmanGroupConstructor, ScryptOptions, RsaPublicKey, RsaPrivateKey, BasePrivateKeyEncodingOptions, KeyPairKeyObjectResult, ED25519KeyPairKeyObjectOptions, ED448KeyPairKeyObjectOptions, X25519KeyPairKeyObjectOptions, X448KeyPairKeyObjectOptions, ECKeyPairKeyObjectOptions, RSAKeyPairKeyObjectOptions, RSAPSSKeyPairKeyObjectOptions, DSAKeyPairKeyObjectOptions, RSAKeyPairOptions, RSAPSSKeyPairOptions, DSAKeyPairOptions, ECKeyPairOptions, ED25519KeyPairOptions, ED448KeyPairOptions, X25519KeyPairOptions, X448KeyPairOptions, KeyPairSyncResult, CipherInfoOptions, CipherInfo, SecureHeapUsage, RandomUUIDOptions, X509CheckOptions, GeneratePrimeOptions, GeneratePrimeOptionsBigInt, GeneratePrimeOptionsArrayBuffer, CheckPrimeOptions, AesCbcParams, AesCtrParams, AesDerivedKeyParams, AesGcmParams, AesKeyAlgorithm, AesKeyGenParams, Algorithm, EcKeyAlgorithm, EcKeyGenParams, EcKeyImportParams, EcdhKeyDeriveParams, EcdsaParams, Ed448Params, HkdfParams, HmacImportParams, HmacKeyAlgorithm, HmacKeyGenParams, JsonWebKey, KeyAlgorithm, Pbkdf2Params, RsaHashedImportParams, RsaHashedKeyAlgorithm, RsaHashedKeyGenParams, RsaKeyAlgorithm, RsaKeyGenParams, RsaOaepParams, RsaOtherPrimesInfo, RsaPssParams, Crypto, CryptoKeyConstructor, CryptoKey, CryptoKeyPair, SubtleCrypto
- Classes: Certificate, Hash, Hmac, KeyObject, Cipher, Decipher, Sign, Verify, DiffieHellman, ECDH, X509Certificate
- Functions: createHash, createHmac, createCipheriv, createCipheriv, createCipheriv, createCipheriv, createDecipheriv, createDecipheriv, createDecipheriv, createDecipheriv, generateKey, generateKeySync, createPrivateKey, createPublicKey, createSecretKey, createSecretKey, createSign, createVerify, createDiffieHellman, createDiffieHellman, createDiffieHellman, createDiffieHellman, createDiffieHellman, getDiffieHellman, createDiffieHellmanGroup, pbkdf2, pbkdf2Sync, randomBytes, randomBytes, pseudoRandomBytes, pseudoRandomBytes, randomInt, randomInt, randomInt, randomInt, randomFillSync, randomFill, randomFill, randomFill, scrypt, scrypt, scryptSync, publicEncrypt, publicDecrypt, privateDecrypt, privateEncrypt, getCiphers, getCurves, getFips, setFips, getHashes, createECDH, timingSafeEqual, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPairSync, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, generateKeyPair, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, sign, sign, verify, verify, diffieHellman, hash, hash, hash, getCipherInfo, hkdf, hkdfSync, secureHeapUsed, randomUUID, generatePrime, generatePrime, generatePrime, generatePrime, generatePrimeSync, generatePrimeSync, generatePrimeSync, generatePrimeSync, checkPrime, checkPrime, checkPrimeSync, setEngine, getRandomValues

### dgram.d.ts
- Imports: node:net, node:dns, node:events
- Exports: dgram
- Interfaces: RemoteInfo, BindOptions, SocketOptions
- Classes: Socket
- Functions: createSocket, createSocket

### diagnostics_channel.d.ts
- Imports: node:async_hooks
- Exports: diagnostics_channel
- Interfaces: TracingChannelSubscribers, TracingChannelCollection
- Classes: Channel, TracingChannel
- Functions: hasSubscribers, channel, subscribe, unsubscribe, tracingChannel

### promises.d.ts
- Imports: node:dns
- Exports: dns/promises
- Interfaces: 
- Classes: Resolver
- Functions: getServers, lookup, lookup, lookup, lookup, lookup, lookupService, resolve, resolve, resolve, resolve, resolve, resolve, resolve, resolve, resolve, resolve, resolve, resolve, resolve, resolve, resolve4, resolve4, resolve4, resolve6, resolve6, resolve6, resolveAny, resolveCaa, resolveCname, resolveMx, resolveNaptr, resolveNs, resolvePtr, resolveSoa, resolveSrv, resolveTxt, reverse, getDefaultResultOrder, setServers, setDefaultResultOrder

### dns.d.ts
- Imports: node:dns/promises
- Exports: dns
- Interfaces: LookupOptions, LookupOneOptions, LookupAllOptions, LookupAddress, ResolveOptions, ResolveWithTtlOptions, RecordWithTtl, AnyARecord, AnyAaaaRecord, CaaRecord, MxRecord, AnyMxRecord, NaptrRecord, AnyNaptrRecord, SoaRecord, AnySoaRecord, SrvRecord, AnySrvRecord, AnyTxtRecord, AnyNsRecord, AnyPtrRecord, AnyCnameRecord, ResolverOptions
- Classes: Resolver
- Functions: lookup, lookup, lookup, lookup, lookup, __promisify__, __promisify__, __promisify__, lookupService, __promisify__, resolve, resolve, resolve, resolve, resolve, resolve, resolve, resolve, resolve, resolve, resolve, resolve, resolve, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, resolve4, resolve4, resolve4, __promisify__, __promisify__, __promisify__, resolve6, resolve6, resolve6, __promisify__, __promisify__, __promisify__, resolveCname, __promisify__, resolveCaa, __promisify__, resolveMx, __promisify__, resolveNaptr, __promisify__, resolveNs, __promisify__, resolvePtr, __promisify__, resolveSoa, __promisify__, resolveSrv, __promisify__, resolveTxt, __promisify__, resolveAny, __promisify__, reverse, getDefaultResultOrder, setServers, getServers, setDefaultResultOrder

### dom-events.d.ts
- Imports: events
- Exports: 
- Interfaces: EventInit, EventListenerOptions, AddEventListenerOptions, EventListener, EventListenerObject, Event, EventTarget
- Classes: 
- Functions: 

### domain.d.ts
- Imports: 
- Exports: domain
- Interfaces: 
- Classes: Domain
- Functions: create

### events.d.ts
- Imports: node:async_hooks
- Exports: 
- Interfaces: EventEmitterOptions, StaticEventEmitterOptions, StaticEventEmitterIteratorOptions, EventEmitter, Abortable, EventEmitterReferencingAsyncResource, EventEmitterAsyncResourceOptions, EventEmitter
- Classes: EventEmitter, EventEmitterAsyncResource
- Functions: 

### promises.d.ts
- Imports: node:events, node:stream, node:stream/web, node:fs, node:readline
- Exports: fs/promises
- Interfaces: FileChangeInfo, FlagAndOpenMode, FileReadResult, FileReadOptions, CreateReadStreamOptions, CreateWriteStreamOptions, ReadableWebStreamOptions, FileHandle
- Classes: 
- Functions: access, copyFile, open, rename, truncate, rmdir, rm, mkdir, mkdir, mkdir, readdir, readdir, readdir, readdir, readlink, readlink, readlink, symlink, lstat, lstat, lstat, stat, stat, stat, statfs, statfs, statfs, link, unlink, chmod, lchmod, lchown, lutimes, chown, utimes, realpath, realpath, realpath, mkdtemp, mkdtemp, mkdtemp, writeFile, appendFile, readFile, readFile, readFile, opendir, watch, watch, watch, cp, glob, glob, glob, glob

### fs.d.ts
- Imports: node:stream, node:events, node:url, node:fs/promises
- Exports: fs
- Interfaces: ObjectEncodingOptions, StatsBase, Stats, StatsFsBase, StatsFs, BigIntStatsFs, StatFsOptions, StatWatcher, FSWatcher, StatSyncFn, RmDirOptions, RmOptions, MakeDirectoryOptions, ReadSyncOptions, ReadAsyncOptions, WatchFileOptions, WatchOptions, StreamOptions, FSImplementation, CreateReadStreamFSImplementation, CreateWriteStreamFSImplementation, ReadStreamOptions, WriteStreamOptions, WriteVResult, ReadVResult, OpenAsBlobOptions, OpenDirOptions, BigIntStats, BigIntOptions, StatOptions, StatSyncOptions, CopyOptionsBase, CopyOptions, CopySyncOptions, GlobOptionsBase, GlobOptionsWithFileTypes, GlobOptionsWithoutFileTypes, GlobOptions
- Classes: Stats, StatsFs, Dirent, Dir, ReadStream, WriteStream
- Functions: rename, __promisify__, renameSync, truncate, truncate, __promisify__, truncateSync, ftruncate, ftruncate, __promisify__, ftruncateSync, chown, __promisify__, chownSync, fchown, __promisify__, fchownSync, lchown, __promisify__, lchownSync, lutimes, __promisify__, lutimesSync, chmod, __promisify__, chmodSync, fchmod, __promisify__, fchmodSync, lchmod, __promisify__, lchmodSync, stat, stat, stat, stat, __promisify__, __promisify__, __promisify__, fstat, fstat, fstat, fstat, __promisify__, __promisify__, __promisify__, fstatSync, fstatSync, fstatSync, lstat, lstat, lstat, lstat, __promisify__, __promisify__, __promisify__, statfs, statfs, statfs, statfs, __promisify__, __promisify__, __promisify__, statfsSync, statfsSync, statfsSync, link, __promisify__, linkSync, symlink, symlink, __promisify__, symlinkSync, readlink, readlink, readlink, readlink, __promisify__, __promisify__, __promisify__, readlinkSync, readlinkSync, readlinkSync, realpath, realpath, realpath, realpath, __promisify__, __promisify__, __promisify__, native, native, native, native, realpathSync, realpathSync, realpathSync, native, native, native, unlink, __promisify__, unlinkSync, rmdir, rmdir, __promisify__, rmdirSync, rm, rm, __promisify__, rmSync, mkdir, mkdir, mkdir, mkdir, __promisify__, __promisify__, __promisify__, mkdirSync, mkdirSync, mkdirSync, mkdtemp, mkdtemp, mkdtemp, mkdtemp, __promisify__, __promisify__, __promisify__, mkdtempSync, mkdtempSync, mkdtempSync, readdir, readdir, readdir, readdir, readdir, __promisify__, __promisify__, __promisify__, __promisify__, readdirSync, readdirSync, readdirSync, readdirSync, close, __promisify__, closeSync, open, open, open, __promisify__, openSync, utimes, __promisify__, utimesSync, futimes, __promisify__, futimesSync, fsync, __promisify__, fsyncSync, write, write, write, write, write, write, write, __promisify__, __promisify__, writeSync, writeSync, read, read, read, __promisify__, __promisify__, __promisify__, readSync, readSync, readFile, readFile, readFile, readFile, __promisify__, __promisify__, __promisify__, readFileSync, readFileSync, readFileSync, writeFile, writeFile, __promisify__, writeFileSync, appendFile, appendFile, __promisify__, appendFileSync, watchFile, watchFile, watchFile, unwatchFile, unwatchFile, watch, watch, watch, watch, exists, __promisify__, existsSync, access, access, __promisify__, accessSync, createReadStream, createWriteStream, fdatasync, __promisify__, fdatasyncSync, copyFile, copyFile, __promisify__, copyFileSync, writev, writev, __promisify__, writevSync, readv, readv, __promisify__, readvSync, openAsBlob, opendirSync, opendir, opendir, __promisify__, cp, cp, cpSync, glob, glob, glob, glob, globSync, globSync, globSync, globSync

### globals.d.ts
- Imports: 
- Exports: 
- Interfaces: NodeDOMException, NodeDOMExceptionConstructor, ErrorConstructor, NodeRequire, RequireResolve, NodeModule, GCFunction, AbortController, AbortSignal, Storage, DOMException, CallSite, ErrnoException, ReadableStream, WritableStream, ReadWriteStream, RefCounted, Require, RequireResolve, RequireExtensions, Module, Dict, ReadOnlyDict, Iterator, AsyncIterator, RequestInit, Request, ResponseInit, Response, FormData, Headers, MessageEvent, WebSocket, EventSource
- Classes: 
- Functions: structuredClone, fetch

### globals.typedarray.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### http.d.ts
- Imports: node:stream, node:url, node:dns, node:events, node:net
- Exports: http
- Interfaces: IncomingHttpHeaders, OutgoingHttpHeaders, ClientRequestArgs, ServerOptions, InformationEvent, AgentOptions, RequestOptions
- Classes: Server, OutgoingMessage, ServerResponse, ClientRequest, IncomingMessage, Agent
- Functions: createServer, createServer, request, request, get, get, validateHeaderName, validateHeaderValue, setMaxIdleHTTPParsers

### http2.d.ts
- Imports: node:fs, node:net, node:stream, node:tls, node:url, node:http
- Exports: node:http, http2
- Interfaces: IncomingHttpStatusHeader, IncomingHttpHeaders, StreamPriorityOptions, StreamState, ServerStreamResponseOptions, StatOptions, ServerStreamFileResponseOptions, ServerStreamFileResponseOptionsWithError, Http2Stream, ClientHttp2Stream, ServerHttp2Stream, Settings, ClientSessionRequestOptions, SessionState, Http2Session, ClientHttp2Session, AlternativeServiceOptions, ServerHttp2Session, SessionOptions, ClientSessionOptions, ServerSessionOptions, SecureClientSessionOptions, SecureServerSessionOptions, ServerOptions, SecureServerOptions, HTTP2ServerCommon, Http2Server, Http2SecureServer
- Classes: Http2ServerRequest, Http2ServerResponse
- Functions: getDefaultSettings, getPackedSettings, getUnpackedSettings, createServer, createServer, createSecureServer, createSecureServer, connect, connect, performServerHandshake

### https.d.ts
- Imports: node:stream, node:tls, node:http, node:url
- Exports: https
- Interfaces: AgentOptions, Server
- Classes: Agent, Server
- Functions: createServer, createServer, request, request, get, get

### index.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### inspector.d.ts
- Imports: inspector
- Exports: inspector, inspector/promises
- Interfaces: InspectorNotification, Domain, GetDomainsReturnType, RemoteObject, CustomPreview, ObjectPreview, PropertyPreview, EntryPreview, PropertyDescriptor, InternalPropertyDescriptor, CallArgument, ExecutionContextDescription, ExceptionDetails, CallFrame, StackTrace, StackTraceId, EvaluateParameterType, AwaitPromiseParameterType, CallFunctionOnParameterType, GetPropertiesParameterType, ReleaseObjectParameterType, ReleaseObjectGroupParameterType, SetCustomObjectFormatterEnabledParameterType, CompileScriptParameterType, RunScriptParameterType, QueryObjectsParameterType, GlobalLexicalScopeNamesParameterType, EvaluateReturnType, AwaitPromiseReturnType, CallFunctionOnReturnType, GetPropertiesReturnType, CompileScriptReturnType, RunScriptReturnType, QueryObjectsReturnType, GlobalLexicalScopeNamesReturnType, ExecutionContextCreatedEventDataType, ExecutionContextDestroyedEventDataType, ExceptionThrownEventDataType, ExceptionRevokedEventDataType, ConsoleAPICalledEventDataType, InspectRequestedEventDataType, Location, ScriptPosition, CallFrame, Scope, SearchMatch, BreakLocation, SetBreakpointsActiveParameterType, SetSkipAllPausesParameterType, SetBreakpointByUrlParameterType, SetBreakpointParameterType, RemoveBreakpointParameterType, GetPossibleBreakpointsParameterType, ContinueToLocationParameterType, PauseOnAsyncCallParameterType, StepIntoParameterType, GetStackTraceParameterType, SearchInContentParameterType, SetScriptSourceParameterType, RestartFrameParameterType, GetScriptSourceParameterType, SetPauseOnExceptionsParameterType, EvaluateOnCallFrameParameterType, SetVariableValueParameterType, SetReturnValueParameterType, SetAsyncCallStackDepthParameterType, SetBlackboxPatternsParameterType, SetBlackboxedRangesParameterType, EnableReturnType, SetBreakpointByUrlReturnType, SetBreakpointReturnType, GetPossibleBreakpointsReturnType, GetStackTraceReturnType, SearchInContentReturnType, SetScriptSourceReturnType, RestartFrameReturnType, GetScriptSourceReturnType, EvaluateOnCallFrameReturnType, ScriptParsedEventDataType, ScriptFailedToParseEventDataType, BreakpointResolvedEventDataType, PausedEventDataType, ConsoleMessage, MessageAddedEventDataType, ProfileNode, Profile, PositionTickInfo, CoverageRange, FunctionCoverage, ScriptCoverage, SetSamplingIntervalParameterType, StartPreciseCoverageParameterType, StopReturnType, TakePreciseCoverageReturnType, GetBestEffortCoverageReturnType, ConsoleProfileStartedEventDataType, ConsoleProfileFinishedEventDataType, SamplingHeapProfileNode, SamplingHeapProfile, StartTrackingHeapObjectsParameterType, StopTrackingHeapObjectsParameterType, TakeHeapSnapshotParameterType, GetObjectByHeapObjectIdParameterType, AddInspectedHeapObjectParameterType, GetHeapObjectIdParameterType, StartSamplingParameterType, GetObjectByHeapObjectIdReturnType, GetHeapObjectIdReturnType, StopSamplingReturnType, GetSamplingProfileReturnType, AddHeapSnapshotChunkEventDataType, ReportHeapSnapshotProgressEventDataType, LastSeenObjectIdEventDataType, HeapStatsUpdateEventDataType, TraceConfig, StartParameterType, GetCategoriesReturnType, DataCollectedEventDataType, WorkerInfo, SendMessageToWorkerParameterType, EnableParameterType, DetachParameterType, AttachedToWorkerEventDataType, DetachedFromWorkerEventDataType, ReceivedMessageFromWorkerEventDataType, Request, Response, Headers, RequestWillBeSentEventDataType, ResponseReceivedEventDataType, LoadingFailedEventDataType, LoadingFinishedEventDataType, NotifyWhenWaitingForDisconnectParameterType, InspectorConsole
- Classes: Session, Session
- Functions: open, close, url, waitForDebugger, requestWillBeSent, responseReceived, loadingFinished, loadingFailed

### module.d.ts
- Imports: node:url, node:worker_threads
- Exports: 
- Interfaces: SourceMapPayload, SourceMapping, SourceOrigin, ImportAttributes, GlobalPreloadContext, ResolveHookContext, ResolveFnOutput, LoadHookContext, LoadFnOutput, RegisterOptions, EnableCompileCacheResult, Module, ImportMeta
- Classes: SourceMap, Module
- Functions: syncBuiltinESMExports, findSourceMap

### net.d.ts
- Imports: node:stream, node:events, node:dns
- Exports: net
- Interfaces: AddressInfo, SocketConstructorOpts, OnReadOpts, ConnectOpts, TcpSocketConnectOpts, IpcSocketConnectOpts, ListenOptions, ServerOpts, DropArgument, TcpNetConnectOpts, IpcNetConnectOpts, SocketAddressInitOptions
- Classes: Socket, Server, BlockList, SocketAddress
- Functions: createServer, createServer, connect, connect, connect, createConnection, createConnection, createConnection, getDefaultAutoSelectFamily, setDefaultAutoSelectFamily, getDefaultAutoSelectFamilyAttemptTimeout, setDefaultAutoSelectFamilyAttemptTimeout, isIP, isIPv4, isIPv6

### os.d.ts
- Imports: 
- Exports: os
- Interfaces: CpuInfo, NetworkInterfaceBase, NetworkInterfaceInfoIPv4, NetworkInterfaceInfoIPv6, UserInfo
- Classes: 
- Functions: hostname, loadavg, uptime, freemem, totalmem, cpus, availableParallelism, type, release, networkInterfaces, homedir, userInfo, userInfo, arch, version, platform, machine, tmpdir, endianness, getPriority, setPriority, setPriority

### path.d.ts
- Imports: 
- Exports: 
- Interfaces: ParsedPath, FormatInputPathObject, PlatformPath
- Classes: 
- Functions: 

### perf_hooks.d.ts
- Imports: node:async_hooks, perf_hooks
- Exports: perf_hooks
- Interfaces: NodeGCPerformanceDetail, UVMetrics, EventLoopUtilization, MarkOptions, MeasureOptions, TimerifyOptions, Performance, EventLoopMonitorOptions, Histogram, IntervalHistogram, RecordableHistogram, CreateHistogramOptions
- Classes: PerformanceEntry, PerformanceMark, PerformanceMeasure, PerformanceNodeTiming, PerformanceObserverEntryList, PerformanceObserver, PerformanceResourceTiming
- Functions: monitorEventLoopDelay, createHistogram

### process.d.ts
- Imports: node:tty, node:worker_threads
- Exports: 
- Interfaces: BuiltInModule, ReadStream, WriteStream, MemoryUsageFn, MemoryUsage, CpuUsage, ProcessRelease, ProcessFeatures, ProcessVersions, Socket, ProcessEnv, HRTime, ProcessPermission, ProcessReport, ResourceUsage, EmitWarningOptions, ProcessConfig, Process
- Classes: 
- Functions: 

### punycode.d.ts
- Imports: 
- Exports: punycode
- Interfaces: ucs2
- Classes: 
- Functions: decode, encode, toUnicode, toASCII

### querystring.d.ts
- Imports: 
- Exports: querystring
- Interfaces: StringifyOptions, ParseOptions, ParsedUrlQuery, ParsedUrlQueryInput
- Classes: 
- Functions: stringify, parse, escape, unescape

### promises.d.ts
- Imports: node:events, node:readline
- Exports: readline/promises
- Interfaces: ReadLineOptions
- Classes: Interface, Readline
- Functions: createInterface, createInterface

### readline.d.ts
- Imports: node:events, node:readline/promises
- Exports: readline
- Interfaces: Key, ReadLineOptions, CursorPos
- Classes: Interface
- Functions: createInterface, createInterface, emitKeypressEvents, clearLine, clearScreenDown, cursorTo, moveCursor

### repl.d.ts
- Imports: node:readline, node:vm, node:util
- Exports: repl
- Interfaces: ReplOptions, REPLCommand
- Classes: REPLServer, Recoverable
- Functions: start

### sea.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: isSea, getAsset, getAsset, getAssetAsBlob, getRawAsset

### sqlite.d.ts
- Imports: 
- Exports: 
- Interfaces: DatabaseSyncOptions, StatementResultingChanges
- Classes: DatabaseSync, StatementSync
- Functions: 

### consumers.d.ts
- Imports: node:buffer, node:stream
- Exports: stream/consumers
- Interfaces: 
- Classes: 
- Functions: buffer, text, arrayBuffer, blob, json

### promises.d.ts
- Imports: node:stream
- Exports: stream/promises
- Interfaces: FinishedOptions
- Classes: 
- Functions: finished, pipeline, pipeline, pipeline, pipeline, pipeline, pipeline, pipeline

### web.d.ts
- Imports: 
- Exports: stream/web
- Interfaces: ReadableWritablePair, StreamPipeOptions, ReadableStreamGenericReader, ReadableStreamReadValueResult, ReadableStreamReadDoneResult, ReadableByteStreamControllerCallback, UnderlyingSinkAbortCallback, UnderlyingSinkCloseCallback, UnderlyingSinkStartCallback, UnderlyingSinkWriteCallback, UnderlyingSourceCancelCallback, UnderlyingSourcePullCallback, UnderlyingSourceStartCallback, TransformerFlushCallback, TransformerStartCallback, TransformerTransformCallback, UnderlyingByteSource, UnderlyingSource, UnderlyingSink, ReadableStreamErrorCallback, ReadableStreamAsyncIterator, ReadableStream, ReadableStreamGetReaderOptions, ReadableStreamDefaultReader, ReadableStreamBYOBReader, ReadableStreamBYOBRequest, ReadableByteStreamController, ReadableStreamDefaultController, Transformer, TransformStream, TransformStreamDefaultController, WritableStream, WritableStreamDefaultWriter, WritableStreamDefaultController, QueuingStrategy, QueuingStrategySize, QueuingStrategyInit, ByteLengthQueuingStrategy, CountQueuingStrategy, TextEncoderStream, TextDecoderOptions, TextDecoderStream, CompressionStream, DecompressionStream, ByteLengthQueuingStrategy, CompressionStream, CountQueuingStrategy, DecompressionStream, ReadableByteStreamController, ReadableStream, ReadableStreamBYOBReader, ReadableStreamBYOBRequest, ReadableStreamDefaultController, ReadableStreamDefaultReader, TextDecoderStream, TextEncoderStream, TransformStream, TransformStreamDefaultController, WritableStream, WritableStreamDefaultController, WritableStreamDefaultWriter
- Classes: 
- Functions: 

### stream.d.ts
- Imports: node:events, node:buffer, node:stream/promises, node:stream/consumers, node:stream/web
- Exports: 
- Interfaces: ArrayOptions, StreamOptions, ReadableOptions, WritableOptions, DuplexOptions, TransformOptions, FinishedOptions, PipelineOptions, Pipe
- Classes: internal, ReadableBase, WritableBase, Stream, Readable, Writable, Duplex, Transform, PassThrough
- Functions: duplexPair, addAbortSignal, getDefaultHighWaterMark, setDefaultHighWaterMark, finished, finished, __promisify__, pipeline, pipeline, pipeline, pipeline, pipeline, pipeline, pipeline, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, __promisify__, isErrored, isReadable

### string_decoder.d.ts
- Imports: 
- Exports: string_decoder
- Interfaces: 
- Classes: StringDecoder
- Functions: 

### test.d.ts
- Imports: node:stream, node:stream
- Exports: 
- Interfaces: TestShard, RunOptions, TestContextAssert, AssertSnapshotOptions, TestOptions, HookOptions, MockFunctionOptions, MockMethodOptions, MockModuleOptions, MockFunctionCall, MockTimersOptions, TestError, TestLocationInfo, DiagnosticData, TestCoverage, TestComplete, TestDequeue, TestEnqueue, TestFail, TestPass, TestPlan, TestStart, TestStderr, TestStdout, TestSummary, ReporterConstructorWrapper
- Classes: TestsStream, TestContext, SuiteContext, MockTracker, MockFunctionContext, MockModuleContext, MockTimers, SpecReporter, LcovReporter
- Functions: run, test, test, test, test, suite, suite, suite, suite, skip, skip, skip, skip, todo, todo, todo, todo, only, only, only, only, describe, describe, describe, describe, skip, skip, skip, skip, todo, todo, todo, todo, only, only, only, only, it, it, it, it, skip, skip, skip, skip, todo, todo, todo, todo, only, only, only, only, skip, skip, skip, skip, todo, todo, todo, todo, only, only, only, only, before, after, beforeEach, afterEach, setDefaultSnapshotSerializers, setResolveSnapshotPath, dot, tap, junit

### promises.d.ts
- Imports: node:timers
- Exports: timers/promises
- Interfaces: Scheduler
- Classes: 
- Functions: setTimeout, setImmediate, setInterval

### timers.d.ts
- Imports: node:events, node:timers/promises
- Exports: timers
- Interfaces: TimerOptions, Timer
- Classes: Immediate, Timeout
- Functions: setTimeout, setTimeout, clearTimeout, setInterval, setInterval, clearInterval, setImmediate, setImmediate, clearImmediate, queueMicrotask

### tls.d.ts
- Imports: node:crypto, node:net, stream
- Exports: tls
- Interfaces: Certificate, PeerCertificate, DetailedPeerCertificate, CipherNameAndProtocol, EphemeralKeyInfo, KeyObject, PxfObject, TLSSocketOptions, CommonConnectionOptions, TlsOptions, PSKCallbackNegotation, ConnectionOptions, SecurePair, SecureContextOptions, SecureContext
- Classes: TLSSocket, Server
- Functions: checkServerIdentity, createServer, createServer, connect, connect, connect, createSecurePair, createSecureContext, getCiphers

### trace_events.d.ts
- Imports: 
- Exports: trace_events
- Interfaces: Tracing, CreateTracingOptions
- Classes: 
- Functions: createTracing, getEnabledCategories

### buffer.buffer.d.ts
- Imports: 
- Exports: 
- Interfaces: BufferConstructor, Buffer
- Classes: 
- Functions: 

### globals.typedarray.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### index.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### tty.d.ts
- Imports: node:net
- Exports: tty
- Interfaces: 
- Classes: ReadStream, WriteStream
- Functions: isatty

### url.d.ts
- Imports: node:buffer, node:http, node:querystring, url
- Exports: url
- Interfaces: UrlObject, Url, UrlWithParsedQuery, UrlWithStringQuery, FileUrlToPathOptions, PathToFileUrlOptions, URLFormatOptions, URLSearchParamsIterator, URLSearchParams, URL, Global
- Classes: URL, URLSearchParams
- Functions: parse, parse, parse, parse, format, format, resolve, domainToASCII, domainToUnicode, fileURLToPath, pathToFileURL, urlToHttpOptions

### util.d.ts
- Imports: node:util/types, util, node:crypto
- Exports: util, util/types
- Interfaces: InspectOptions, InspectOptionsStylized, StacktraceObject, DebugLogger, CustomPromisifyLegacy, CustomPromisifySymbol, EncodeIntoResult, ParseArgsOptionConfig, ParseArgsOptionsConfig, ParseArgsConfig
- Classes: TextDecoder, TextEncoder, MIMEType, MIMEParams
- Functions: format, formatWithOptions, getCallSite, getSystemErrorName, getSystemErrorMap, log, toUSVString, transferableAbortController, transferableAbortSignal, aborted, inspect, inspect, isArray, isRegExp, isDate, isError, inherits, debuglog, isBoolean, isBuffer, isFunction, isNull, isNullOrUndefined, isNumber, isObject, isPrimitive, isString, isSymbol, isUndefined, deprecate, isDeepStrictEqual, stripVTControlCharacters, callbackify, callbackify, callbackify, callbackify, callbackify, callbackify, callbackify, callbackify, callbackify, callbackify, callbackify, callbackify, callbackify, callbackify, promisify, promisify, promisify, promisify, promisify, promisify, promisify, promisify, promisify, promisify, promisify, promisify, promisify, promisify, parseEnv, styleText, parseArgs, isAnyArrayBuffer, isArgumentsObject, isArrayBuffer, isArrayBufferView, isAsyncFunction, isBigInt64Array, isBigUint64Array, isBooleanObject, isBoxedPrimitive, isDataView, isDate, isExternal, isFloat32Array, isFloat64Array, isGeneratorFunction, isGeneratorObject, isInt8Array, isInt16Array, isInt32Array, isMap, isMapIterator, isModuleNamespaceObject, isNativeError, isNumberObject, isPromise, isProxy, isRegExp, isSet, isSetIterator, isSharedArrayBuffer, isStringObject, isSymbolObject, isTypedArray, isUint8Array, isUint8ClampedArray, isUint16Array, isUint32Array, isWeakMap, isWeakSet, isKeyObject, isCryptoKey

### v8.d.ts
- Imports: node:stream
- Exports: v8
- Interfaces: HeapSpaceInfo, HeapInfo, HeapCodeStatistics, HeapSnapshotOptions, GCProfilerResult, HeapStatistics, HeapSpaceStatistics, Init, Before, After, Settled, HookCallbacks, PromiseHooks, StartupSnapshot
- Classes: Serializer, DefaultSerializer, Deserializer, DefaultDeserializer, GCProfiler
- Functions: cachedDataVersionTag, getHeapStatistics, getHeapSpaceStatistics, setFlagsFromString, queryObjects, queryObjects, queryObjects, getHeapSnapshot, writeHeapSnapshot, getHeapCodeStatistics, serialize, deserialize, takeCoverage, stopCoverage, setHeapSnapshotNearHeapLimit

### vm.d.ts
- Imports: node:module
- Exports: vm
- Interfaces: Context, BaseOptions, ScriptOptions, RunningScriptOptions, RunningScriptInNewContextOptions, RunningCodeOptions, RunningCodeInNewContextOptions, CompileFunctionOptions, CreateContextOptions, MeasureMemoryOptions, MemoryMeasurement, ModuleEvaluateOptions, SourceTextModuleOptions, SyntheticModuleOptions
- Classes: Script, Module, SourceTextModule, SyntheticModule
- Functions: createContext, isContext, runInContext, runInNewContext, runInThisContext, compileFunction, measureMemory

### wasi.d.ts
- Imports: 
- Exports: wasi
- Interfaces: WASIOptions
- Classes: WASI
- Functions: 

### worker_threads.d.ts
- Imports: node:buffer, node:vm, node:events, node:perf_hooks, node:fs/promises, node:stream, node:url, node:crypto, worker_threads
- Exports: worker_threads
- Interfaces: WorkerPerformance, WorkerOptions, ResourceLimits, BroadcastChannel
- Classes: MessageChannel, MessagePort, Worker, BroadcastChannel
- Functions: markAsUntransferable, isMarkedAsUntransferable, markAsUncloneable, moveMessagePortToContext, receiveMessageOnPort, getEnvironmentData, setEnvironmentData

### zlib.d.ts
- Imports: node:stream
- Exports: zlib
- Interfaces: ZlibOptions, BrotliOptions, Zlib, ZlibParams, ZlibReset, BrotliCompress, BrotliDecompress, Gzip, Gunzip, Deflate, Inflate, DeflateRaw, InflateRaw, Unzip
- Classes: 
- Functions: crc32, createBrotliCompress, createBrotliDecompress, createGzip, createGunzip, createDeflate, createInflate, createDeflateRaw, createInflateRaw, createUnzip, brotliCompress, brotliCompress, __promisify__, brotliCompressSync, brotliDecompress, brotliDecompress, __promisify__, brotliDecompressSync, deflate, deflate, __promisify__, deflateSync, deflateRaw, deflateRaw, __promisify__, deflateRawSync, gzip, gzip, __promisify__, gzipSync, gunzip, gunzip, __promisify__, gunzipSync, inflate, inflate, __promisify__, inflateSync, inflateRaw, inflateRaw, __promisify__, inflateRawSync, unzip, unzip, __promisify__, unzipSync

### acorn.d.ts
- Imports: 
- Exports: 
- Interfaces: Node, SourceLocation, Position, Identifier, Literal, Program, Function, ExpressionStatement, BlockStatement, EmptyStatement, DebuggerStatement, WithStatement, ReturnStatement, LabeledStatement, BreakStatement, ContinueStatement, IfStatement, SwitchStatement, SwitchCase, ThrowStatement, TryStatement, CatchClause, WhileStatement, DoWhileStatement, ForStatement, ForInStatement, FunctionDeclaration, VariableDeclaration, VariableDeclarator, ThisExpression, ArrayExpression, ObjectExpression, Property, FunctionExpression, UnaryExpression, UpdateExpression, BinaryExpression, AssignmentExpression, LogicalExpression, MemberExpression, ConditionalExpression, CallExpression, NewExpression, SequenceExpression, ForOfStatement, Super, SpreadElement, ArrowFunctionExpression, YieldExpression, TemplateLiteral, TaggedTemplateExpression, TemplateElement, AssignmentProperty, ObjectPattern, ArrayPattern, RestElement, AssignmentPattern, Class, ClassBody, MethodDefinition, ClassDeclaration, ClassExpression, MetaProperty, ImportDeclaration, ImportSpecifier, ImportDefaultSpecifier, ImportNamespaceSpecifier, ImportAttribute, ExportNamedDeclaration, ExportSpecifier, AnonymousFunctionDeclaration, AnonymousClassDeclaration, ExportDefaultDeclaration, ExportAllDeclaration, AwaitExpression, ChainExpression, ImportExpression, ParenthesizedExpression, PropertyDefinition, PrivateIdentifier, StaticBlock, Options, Comment
- Classes: Parser, TokenType, Token
- Functions: parse, parseExpressionAt, tokenizer, getLineInfo

### walk.d.ts
- Imports: acorn
- Exports: 
- Interfaces: Found
- Classes: 
- Functions: simple, ancestor, recursive, full, fullAncestor, make, findNodeAt, findNodeAround

### index.d.ts
- Imports: 
- Exports: 
- Interfaces: Spec, Options
- Classes: 
- Functions: arg, flag

### index.d.ts
- Imports: 
- Exports: 
- Interfaces: ErrorOptions, ParseOptions, HelpContext, AddHelpTextContext, OutputConfiguration, CommandOptions, ExecutableCommandOptions, ParseOptionsResult
- Classes: CommanderError, InvalidArgumentError, Argument, Option, Help, Command
- Functions: createCommand, createOption, createArgument

### create-require.d.ts
- Imports: url
- Exports: 
- Interfaces: 
- Classes: 
- Functions: createRequire

### index.d.ts
- Imports: 
- Exports: 
- Interfaces: Constructor, SpecializedConstructor
- Classes: BaseError
- Functions: makeError, makeError, makeError

### bin-cwd.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### bin-esm.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### bin-script-deprecated.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### bin-script.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### bin-transpile.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### bin.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: main

### argv-payload.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### child-entrypoint.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### child-loader.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### child-require.d.ts
- Imports: 
- Exports: 
- Interfaces: EventEmitterInternals
- Classes: 
- Functions: onWarning

### spawn-child.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### cjs-resolve-hooks.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### configuration.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### esm.d.ts
- Imports: ./index
- Exports: 
- Interfaces: NodeLoaderHooksAPI1, NodeLoaderHooksAPI2, NodeImportAssertions, NodeImportAssertions
- Classes: 
- Functions: createEsmHooks

### file-extensions.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### index.d.ts
- Imports: make-error, typescript, ./ts-compiler-types, ./esm
- Exports: ./repl, ./transpilers/types, ./esm
- Interfaces: Process, CreateOptions, RegisterOptions, TsConfigOptions, TypeInfo, Service
- Classes: TSError
- Functions: register, register, create

### module-type-classifier.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### node-module-type-classifier.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### repl.d.ts
- Imports: ./index
- Exports: 
- Interfaces: ReplService, CreateReplOptions
- Classes: EvalState
- Functions: createRepl, createEvalAwarePartialHost

### resolver-functions.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### swc.d.ts
- Imports: @swc/wasm, ./types
- Exports: 
- Interfaces: SwcTranspilerOptions
- Classes: 
- Functions: create

### types.d.ts
- Imports: typescript, ../index
- Exports: 
- Interfaces: TranspilerModule, CreateTranspilerOptions, Transpiler, TranspileOptions, TranspileOutput
- Classes: 
- Functions: 

### ts-compiler-types.d.ts
- Imports: typescript
- Exports: 
- Interfaces: TSCommon, LanguageServiceHost
- Classes: 
- Functions: 

### ts-internals.d.ts
- Imports: typescript
- Exports: 
- Interfaces: 
- Classes: 
- Functions: getUseDefineForClassFields, getEmitScriptTarget

### ts-transpile-module.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### tsconfig-schema.d.ts
- Imports: ./index
- Exports: 
- Interfaces: TsConfigSchema
- Classes: 
- Functions: 

### tsconfigs.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### util.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: cachedLookup

### lib.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.decorators.d.ts
- Imports: 
- Exports: 
- Interfaces: ClassDecoratorContext, ClassMethodDecoratorContext, ClassGetterDecoratorContext, ClassSetterDecoratorContext, ClassAccessorDecoratorContext, ClassAccessorDecoratorTarget, ClassAccessorDecoratorResult, ClassFieldDecoratorContext
- Classes: 
- Functions: 

### lib.decorators.legacy.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.dom.asynciterable.d.ts
- Imports: 
- Exports: 
- Interfaces: FileSystemDirectoryHandleAsyncIterator, FileSystemDirectoryHandle, ReadableStreamAsyncIterator, ReadableStream
- Classes: 
- Functions: 

### lib.dom.d.ts
- Imports: 
- Exports: 
- Interfaces: AddEventListenerOptions, AddressErrors, AesCbcParams, AesCtrParams, AesDerivedKeyParams, AesGcmParams, AesKeyAlgorithm, AesKeyGenParams, Algorithm, AnalyserOptions, AnimationEventInit, AnimationPlaybackEventInit, AssignedNodesOptions, AudioBufferOptions, AudioBufferSourceOptions, AudioConfiguration, AudioContextOptions, AudioDataCopyToOptions, AudioDataInit, AudioDecoderConfig, AudioDecoderInit, AudioDecoderSupport, AudioEncoderConfig, AudioEncoderInit, AudioEncoderSupport, AudioNodeOptions, AudioProcessingEventInit, AudioTimestamp, AudioWorkletNodeOptions, AuthenticationExtensionsClientInputs, AuthenticationExtensionsClientInputsJSON, AuthenticationExtensionsClientOutputs, AuthenticationExtensionsPRFInputs, AuthenticationExtensionsPRFOutputs, AuthenticationExtensionsPRFValues, AuthenticatorSelectionCriteria, AvcEncoderConfig, BiquadFilterOptions, BlobEventInit, BlobPropertyBag, CSSMatrixComponentOptions, CSSNumericType, CSSStyleSheetInit, CacheQueryOptions, CanvasRenderingContext2DSettings, CaretPositionFromPointOptions, ChannelMergerOptions, ChannelSplitterOptions, CheckVisibilityOptions, ClientQueryOptions, ClipboardEventInit, ClipboardItemOptions, CloseEventInit, CompositionEventInit, ComputedEffectTiming, ComputedKeyframe, ConstantSourceOptions, ConstrainBooleanParameters, ConstrainDOMStringParameters, ConstrainDoubleRange, ConstrainULongRange, ContentVisibilityAutoStateChangeEventInit, ConvolverOptions, CredentialCreationOptions, CredentialPropertiesOutput, CredentialRequestOptions, CryptoKeyPair, CustomEventInit, DOMMatrix2DInit, DOMMatrixInit, DOMPointInit, DOMQuadInit, DOMRectInit, DelayOptions, DeviceMotionEventAccelerationInit, DeviceMotionEventInit, DeviceMotionEventRotationRateInit, DeviceOrientationEventInit, DisplayMediaStreamOptions, DocumentTimelineOptions, DoubleRange, DragEventInit, DynamicsCompressorOptions, EcKeyAlgorithm, EcKeyGenParams, EcKeyImportParams, EcdhKeyDeriveParams, EcdsaParams, EffectTiming, ElementCreationOptions, ElementDefinitionOptions, EncodedAudioChunkInit, EncodedAudioChunkMetadata, EncodedVideoChunkInit, EncodedVideoChunkMetadata, ErrorEventInit, EventInit, EventListenerOptions, EventModifierInit, EventSourceInit, FilePropertyBag, FileSystemCreateWritableOptions, FileSystemFlags, FileSystemGetDirectoryOptions, FileSystemGetFileOptions, FileSystemRemoveOptions, FocusEventInit, FocusOptions, FontFaceDescriptors, FontFaceSetLoadEventInit, FormDataEventInit, FullscreenOptions, GainOptions, GamepadEffectParameters, GamepadEventInit, GetAnimationsOptions, GetHTMLOptions, GetNotificationOptions, GetRootNodeOptions, HashChangeEventInit, HkdfParams, HmacImportParams, HmacKeyAlgorithm, HmacKeyGenParams, IDBDatabaseInfo, IDBIndexParameters, IDBObjectStoreParameters, IDBTransactionOptions, IDBVersionChangeEventInit, IIRFilterOptions, IdleRequestOptions, ImageBitmapOptions, ImageBitmapRenderingContextSettings, ImageDataSettings, ImageEncodeOptions, InputEventInit, IntersectionObserverInit, JsonWebKey, KeyAlgorithm, KeyboardEventInit, Keyframe, KeyframeAnimationOptions, KeyframeEffectOptions, LockInfo, LockManagerSnapshot, LockOptions, MIDIConnectionEventInit, MIDIMessageEventInit, MIDIOptions, MediaCapabilitiesDecodingInfo, MediaCapabilitiesEncodingInfo, MediaCapabilitiesInfo, MediaConfiguration, MediaDecodingConfiguration, MediaElementAudioSourceOptions, MediaEncodingConfiguration, MediaEncryptedEventInit, MediaImage, MediaKeyMessageEventInit, MediaKeySystemConfiguration, MediaKeySystemMediaCapability, MediaKeysPolicy, MediaMetadataInit, MediaPositionState, MediaQueryListEventInit, MediaRecorderOptions, MediaSessionActionDetails, MediaStreamAudioSourceOptions, MediaStreamConstraints, MediaStreamTrackEventInit, MediaTrackCapabilities, MediaTrackConstraintSet, MediaTrackConstraints, MediaTrackSettings, MediaTrackSupportedConstraints, MessageEventInit, MouseEventInit, MultiCacheQueryOptions, MutationObserverInit, NavigationPreloadState, NotificationOptions, OfflineAudioCompletionEventInit, OfflineAudioContextOptions, OptionalEffectTiming, OpusEncoderConfig, OscillatorOptions, PageTransitionEventInit, PannerOptions, PayerErrors, PaymentCurrencyAmount, PaymentDetailsBase, PaymentDetailsInit, PaymentDetailsModifier, PaymentDetailsUpdate, PaymentItem, PaymentMethodChangeEventInit, PaymentMethodData, PaymentOptions, PaymentRequestUpdateEventInit, PaymentShippingOption, PaymentValidationErrors, Pbkdf2Params, PerformanceMarkOptions, PerformanceMeasureOptions, PerformanceObserverInit, PeriodicWaveConstraints, PeriodicWaveOptions, PermissionDescriptor, PictureInPictureEventInit, PlaneLayout, PointerEventInit, PointerLockOptions, PopStateEventInit, PositionOptions, ProgressEventInit, PromiseRejectionEventInit, PropertyDefinition, PropertyIndexedKeyframes, PublicKeyCredentialCreationOptions, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialDescriptor, PublicKeyCredentialDescriptorJSON, PublicKeyCredentialEntity, PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRequestOptionsJSON, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, PublicKeyCredentialUserEntityJSON, PushSubscriptionJSON, PushSubscriptionOptionsInit, QueuingStrategy, QueuingStrategyInit, RTCAnswerOptions, RTCCertificateExpiration, RTCConfiguration, RTCDTMFToneChangeEventInit, RTCDataChannelEventInit, RTCDataChannelInit, RTCDtlsFingerprint, RTCEncodedAudioFrameMetadata, RTCEncodedVideoFrameMetadata, RTCErrorEventInit, RTCErrorInit, RTCIceCandidateInit, RTCIceCandidatePairStats, RTCIceServer, RTCInboundRtpStreamStats, RTCLocalSessionDescriptionInit, RTCOfferAnswerOptions, RTCOfferOptions, RTCOutboundRtpStreamStats, RTCPeerConnectionIceErrorEventInit, RTCPeerConnectionIceEventInit, RTCReceivedRtpStreamStats, RTCRtcpParameters, RTCRtpCapabilities, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpContributingSource, RTCRtpEncodingParameters, RTCRtpHeaderExtensionCapability, RTCRtpHeaderExtensionParameters, RTCRtpParameters, RTCRtpReceiveParameters, RTCRtpSendParameters, RTCRtpStreamStats, RTCRtpSynchronizationSource, RTCRtpTransceiverInit, RTCSentRtpStreamStats, RTCSessionDescriptionInit, RTCSetParameterOptions, RTCStats, RTCTrackEventInit, RTCTransportStats, ReadableStreamGetReaderOptions, ReadableStreamIteratorOptions, ReadableStreamReadDoneResult, ReadableStreamReadValueResult, ReadableWritablePair, RegistrationOptions, ReportingObserverOptions, RequestInit, ResizeObserverOptions, ResponseInit, RsaHashedImportParams, RsaHashedKeyAlgorithm, RsaHashedKeyGenParams, RsaKeyAlgorithm, RsaKeyGenParams, RsaOaepParams, RsaOtherPrimesInfo, RsaPssParams, SVGBoundingBoxOptions, ScrollIntoViewOptions, ScrollOptions, ScrollToOptions, SecurityPolicyViolationEventInit, ShadowRootInit, ShareData, SpeechSynthesisErrorEventInit, SpeechSynthesisEventInit, StaticRangeInit, StereoPannerOptions, StorageEstimate, StorageEventInit, StreamPipeOptions, StructuredSerializeOptions, SubmitEventInit, TextDecodeOptions, TextDecoderOptions, TextEncoderEncodeIntoResult, ToggleEventInit, TouchEventInit, TouchInit, TrackEventInit, Transformer, TransitionEventInit, UIEventInit, ULongRange, UnderlyingByteSource, UnderlyingDefaultSource, UnderlyingSink, UnderlyingSource, ValidityStateFlags, VideoColorSpaceInit, VideoConfiguration, VideoDecoderConfig, VideoDecoderInit, VideoDecoderSupport, VideoEncoderConfig, VideoEncoderEncodeOptions, VideoEncoderEncodeOptionsForAvc, VideoEncoderInit, VideoEncoderSupport, VideoFrameBufferInit, VideoFrameCallbackMetadata, VideoFrameCopyToOptions, VideoFrameInit, WaveShaperOptions, WebGLContextAttributes, WebGLContextEventInit, WebTransportCloseInfo, WebTransportErrorOptions, WebTransportHash, WebTransportOptions, WebTransportSendStreamOptions, WheelEventInit, WindowPostMessageOptions, WorkerOptions, WorkletOptions, WriteParams, ANGLE_instanced_arrays, ARIAMixin, AbortController, AbortSignalEventMap, AbortSignal, AbstractRange, AbstractWorkerEventMap, AbstractWorker, AnalyserNode, Animatable, AnimationEventMap, Animation, AnimationEffect, AnimationEvent, AnimationFrameProvider, AnimationPlaybackEvent, AnimationTimeline, Attr, AudioBuffer, AudioBufferSourceNode, AudioContext, AudioData, AudioDecoderEventMap, AudioDecoder, AudioDestinationNode, AudioEncoderEventMap, AudioEncoder, AudioListener, AudioNode, AudioParam, AudioParamMap, AudioProcessingEvent, AudioScheduledSourceNodeEventMap, AudioScheduledSourceNode, AudioWorklet, AudioWorkletNodeEventMap, AudioWorkletNode, AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, AuthenticatorResponse, BarProp, BaseAudioContextEventMap, BaseAudioContext, BeforeUnloadEvent, BiquadFilterNode, Blob, BlobEvent, Body, BroadcastChannelEventMap, BroadcastChannel, ByteLengthQueuingStrategy, CDATASection, CSSAnimation, CSSConditionRule, CSSContainerRule, CSSCounterStyleRule, CSSFontFaceRule, CSSFontFeatureValuesRule, CSSFontPaletteValuesRule, CSSGroupingRule, CSSImageValue, CSSImportRule, CSSKeyframeRule, CSSKeyframesRule, CSSKeywordValue, CSSLayerBlockRule, CSSLayerStatementRule, CSSMathClamp, CSSMathInvert, CSSMathMax, CSSMathMin, CSSMathNegate, CSSMathProduct, CSSMathSum, CSSMathValue, CSSMatrixComponent, CSSMediaRule, CSSNamespaceRule, CSSNumericArray, CSSNumericValue, CSSPageRule, CSSPerspective, CSSPropertyRule, CSSRotate, CSSRule, CSSRuleList, CSSScale, CSSScopeRule, CSSSkew, CSSSkewX, CSSSkewY, CSSStartingStyleRule, CSSStyleDeclaration, CSSStyleRule, CSSStyleSheet, CSSStyleValue, CSSSupportsRule, CSSTransformComponent, CSSTransformValue, CSSTransition, CSSTranslate, CSSUnitValue, CSSUnparsedValue, CSSVariableReferenceValue, Cache, CacheStorage, CanvasCaptureMediaStreamTrack, CanvasCompositing, CanvasDrawImage, CanvasDrawPath, CanvasFillStrokeStyles, CanvasFilters, CanvasGradient, CanvasImageData, CanvasImageSmoothing, CanvasPath, CanvasPathDrawingStyles, CanvasPattern, CanvasRect, CanvasRenderingContext2D, CanvasShadowStyles, CanvasState, CanvasText, CanvasTextDrawingStyles, CanvasTransform, CanvasUserInterface, CaretPosition, ChannelMergerNode, ChannelSplitterNode, CharacterData, ChildNode, ClientRect, Clipboard, ClipboardEvent, ClipboardItem, CloseEvent, Comment, CompositionEvent, CompressionStream, ConstantSourceNode, ContentVisibilityAutoStateChangeEvent, ConvolverNode, CountQueuingStrategy, Credential, CredentialsContainer, Crypto, CryptoKey, CustomElementRegistry, CustomEvent, CustomStateSet, DOMException, DOMImplementation, DOMMatrix, DOMMatrixReadOnly, DOMParser, DOMPoint, DOMPointReadOnly, DOMQuad, DOMRect, DOMRectList, DOMRectReadOnly, DOMStringList, DOMStringMap, DOMTokenList, DataTransfer, DataTransferItem, DataTransferItemList, DecompressionStream, DelayNode, DeviceMotionEvent, DeviceMotionEventAcceleration, DeviceMotionEventRotationRate, DeviceOrientationEvent, DocumentEventMap, Document, DocumentFragment, DocumentOrShadowRoot, DocumentTimeline, DocumentType, DragEvent, DynamicsCompressorNode, EXT_blend_minmax, EXT_color_buffer_float, EXT_color_buffer_half_float, EXT_float_blend, EXT_frag_depth, EXT_sRGB, EXT_shader_texture_lod, EXT_texture_compression_bptc, EXT_texture_compression_rgtc, EXT_texture_filter_anisotropic, EXT_texture_norm16, ElementEventMap, Element, ElementCSSInlineStyle, ElementContentEditable, ElementInternals, EncodedAudioChunk, EncodedVideoChunk, ErrorEvent, Event, EventCounts, EventListener, EventListenerObject, EventSourceEventMap, EventSource, EventTarget, External, File, FileList, FileReaderEventMap, FileReader, FileSystem, FileSystemDirectoryEntry, FileSystemDirectoryHandle, FileSystemDirectoryReader, FileSystemEntry, FileSystemFileEntry, FileSystemFileHandle, FileSystemHandle, FileSystemWritableFileStream, FocusEvent, FontFace, FontFaceSetEventMap, FontFaceSet, FontFaceSetLoadEvent, FontFaceSource, FormData, FormDataEvent, FragmentDirective, GainNode, Gamepad, GamepadButton, GamepadEvent, GamepadHapticActuator, GenericTransformStream, Geolocation, GeolocationCoordinates, GeolocationPosition, GeolocationPositionError, GlobalEventHandlersEventMap, GlobalEventHandlers, HTMLAllCollection, HTMLAnchorElement, HTMLAreaElement, HTMLAudioElement, HTMLBRElement, HTMLBaseElement, HTMLBodyElementEventMap, HTMLBodyElement, HTMLButtonElement, HTMLCanvasElement, HTMLCollectionBase, HTMLCollection, HTMLCollectionOf, HTMLDListElement, HTMLDataElement, HTMLDataListElement, HTMLDetailsElement, HTMLDialogElement, HTMLDirectoryElement, HTMLDivElement, HTMLDocument, HTMLElementEventMap, HTMLElement, HTMLEmbedElement, HTMLFieldSetElement, HTMLFontElement, HTMLFormControlsCollection, HTMLFormElement, HTMLFrameElement, HTMLFrameSetElementEventMap, HTMLFrameSetElement, HTMLHRElement, HTMLHeadElement, HTMLHeadingElement, HTMLHtmlElement, HTMLHyperlinkElementUtils, HTMLIFrameElement, HTMLImageElement, HTMLInputElement, HTMLLIElement, HTMLLabelElement, HTMLLegendElement, HTMLLinkElement, HTMLMapElement, HTMLMarqueeElement, HTMLMediaElementEventMap, HTMLMediaElement, HTMLMenuElement, HTMLMetaElement, HTMLMeterElement, HTMLModElement, HTMLOListElement, HTMLObjectElement, HTMLOptGroupElement, HTMLOptionElement, HTMLOptionsCollection, HTMLOrSVGElement, HTMLOutputElement, HTMLParagraphElement, HTMLParamElement, HTMLPictureElement, HTMLPreElement, HTMLProgressElement, HTMLQuoteElement, HTMLScriptElement, HTMLSelectElement, HTMLSlotElement, HTMLSourceElement, HTMLSpanElement, HTMLStyleElement, HTMLTableCaptionElement, HTMLTableCellElement, HTMLTableColElement, HTMLTableDataCellElement, HTMLTableElement, HTMLTableHeaderCellElement, HTMLTableRowElement, HTMLTableSectionElement, HTMLTemplateElement, HTMLTextAreaElement, HTMLTimeElement, HTMLTitleElement, HTMLTrackElement, HTMLUListElement, HTMLUnknownElement, HTMLVideoElementEventMap, HTMLVideoElement, HashChangeEvent, Headers, Highlight, HighlightRegistry, History, IDBCursor, IDBCursorWithValue, IDBDatabaseEventMap, IDBDatabase, IDBFactory, IDBIndex, IDBKeyRange, IDBObjectStore, IDBOpenDBRequestEventMap, IDBOpenDBRequest, IDBRequestEventMap, IDBRequest, IDBTransactionEventMap, IDBTransaction, IDBVersionChangeEvent, IIRFilterNode, IdleDeadline, ImageBitmap, ImageBitmapRenderingContext, ImageData, ImportMeta, InputDeviceInfo, InputEvent, IntersectionObserver, IntersectionObserverEntry, KHR_parallel_shader_compile, KeyboardEvent, KeyframeEffect, LargestContentfulPaint, LinkStyle, Location, Lock, LockManager, MIDIAccessEventMap, MIDIAccess, MIDIConnectionEvent, MIDIInputEventMap, MIDIInput, MIDIInputMap, MIDIMessageEvent, MIDIOutput, MIDIOutputMap, MIDIPortEventMap, MIDIPort, MathMLElementEventMap, MathMLElement, MediaCapabilities, MediaDeviceInfo, MediaDevicesEventMap, MediaDevices, MediaElementAudioSourceNode, MediaEncryptedEvent, MediaError, MediaKeyMessageEvent, MediaKeySessionEventMap, MediaKeySession, MediaKeyStatusMap, MediaKeySystemAccess, MediaKeys, MediaList, MediaMetadata, MediaQueryListEventMap, MediaQueryList, MediaQueryListEvent, MediaRecorderEventMap, MediaRecorder, MediaSession, MediaSourceEventMap, MediaSource, MediaSourceHandle, MediaStreamEventMap, MediaStream, MediaStreamAudioDestinationNode, MediaStreamAudioSourceNode, MediaStreamTrackEventMap, MediaStreamTrack, MediaStreamTrackEvent, MessageChannel, MessageEvent, MessagePortEventMap, MessagePort, MimeType, MimeTypeArray, MouseEvent, MutationObserver, MutationRecord, NamedNodeMap, NavigationPreloadManager, Navigator, NavigatorAutomationInformation, NavigatorBadge, NavigatorConcurrentHardware, NavigatorContentUtils, NavigatorCookies, NavigatorID, NavigatorLanguage, NavigatorLocks, NavigatorOnLine, NavigatorPlugins, NavigatorStorage, Node, NodeIterator, NodeList, NodeListOf, NonDocumentTypeChildNode, NonElementParentNode, NotificationEventMap, Notification, OES_draw_buffers_indexed, OES_element_index_uint, OES_fbo_render_mipmap, OES_standard_derivatives, OES_texture_float, OES_texture_float_linear, OES_texture_half_float, OES_texture_half_float_linear, OES_vertex_array_object, OVR_multiview2, OfflineAudioCompletionEvent, OfflineAudioContextEventMap, OfflineAudioContext, OffscreenCanvasEventMap, OffscreenCanvas, OffscreenCanvasRenderingContext2D, OscillatorNode, OverconstrainedError, PageTransitionEvent, PannerNode, ParentNode, Path2D, PaymentAddress, PaymentMethodChangeEvent, PaymentRequestEventMap, PaymentRequest, PaymentRequestUpdateEvent, PaymentResponseEventMap, PaymentResponse, PerformanceEventMap, Performance, PerformanceEntry, PerformanceEventTiming, PerformanceMark, PerformanceMeasure, PerformanceNavigation, PerformanceNavigationTiming, PerformanceObserver, PerformanceObserverEntryList, PerformancePaintTiming, PerformanceResourceTiming, PerformanceServerTiming, PerformanceTiming, PeriodicWave, PermissionStatusEventMap, PermissionStatus, Permissions, PictureInPictureEvent, PictureInPictureWindowEventMap, PictureInPictureWindow, Plugin, PluginArray, PointerEvent, PopStateEvent, PopoverInvokerElement, ProcessingInstruction, ProgressEvent, PromiseRejectionEvent, PublicKeyCredential, PushManager, PushSubscription, PushSubscriptionOptions, RTCCertificate, RTCDTMFSenderEventMap, RTCDTMFSender, RTCDTMFToneChangeEvent, RTCDataChannelEventMap, RTCDataChannel, RTCDataChannelEvent, RTCDtlsTransportEventMap, RTCDtlsTransport, RTCEncodedAudioFrame, RTCEncodedVideoFrame, RTCError, RTCErrorEvent, RTCIceCandidate, RTCIceCandidatePair, RTCIceTransportEventMap, RTCIceTransport, RTCPeerConnectionEventMap, RTCPeerConnection, RTCPeerConnectionIceErrorEvent, RTCPeerConnectionIceEvent, RTCRtpReceiver, RTCRtpScriptTransform, RTCRtpSender, RTCRtpTransceiver, RTCSctpTransportEventMap, RTCSctpTransport, RTCSessionDescription, RTCStatsReport, RTCTrackEvent, RadioNodeList, Range, ReadableByteStreamController, ReadableStream, ReadableStreamBYOBReader, ReadableStreamBYOBRequest, ReadableStreamDefaultController, ReadableStreamDefaultReader, ReadableStreamGenericReader, RemotePlaybackEventMap, RemotePlayback, Report, ReportBody, ReportingObserver, Request, ResizeObserver, ResizeObserverEntry, ResizeObserverSize, Response, SVGAElement, SVGAngle, SVGAnimateElement, SVGAnimateMotionElement, SVGAnimateTransformElement, SVGAnimatedAngle, SVGAnimatedBoolean, SVGAnimatedEnumeration, SVGAnimatedInteger, SVGAnimatedLength, SVGAnimatedLengthList, SVGAnimatedNumber, SVGAnimatedNumberList, SVGAnimatedPoints, SVGAnimatedPreserveAspectRatio, SVGAnimatedRect, SVGAnimatedString, SVGAnimatedTransformList, SVGAnimationElement, SVGCircleElement, SVGClipPathElement, SVGComponentTransferFunctionElement, SVGDefsElement, SVGDescElement, SVGElementEventMap, SVGElement, SVGEllipseElement, SVGFEBlendElement, SVGFEColorMatrixElement, SVGFEComponentTransferElement, SVGFECompositeElement, SVGFEConvolveMatrixElement, SVGFEDiffuseLightingElement, SVGFEDisplacementMapElement, SVGFEDistantLightElement, SVGFEDropShadowElement, SVGFEFloodElement, SVGFEFuncAElement, SVGFEFuncBElement, SVGFEFuncGElement, SVGFEFuncRElement, SVGFEGaussianBlurElement, SVGFEImageElement, SVGFEMergeElement, SVGFEMergeNodeElement, SVGFEMorphologyElement, SVGFEOffsetElement, SVGFEPointLightElement, SVGFESpecularLightingElement, SVGFESpotLightElement, SVGFETileElement, SVGFETurbulenceElement, SVGFilterElement, SVGFilterPrimitiveStandardAttributes, SVGFitToViewBox, SVGForeignObjectElement, SVGGElement, SVGGeometryElement, SVGGradientElement, SVGGraphicsElement, SVGImageElement, SVGLength, SVGLengthList, SVGLineElement, SVGLinearGradientElement, SVGMPathElement, SVGMarkerElement, SVGMaskElement, SVGMetadataElement, SVGNumber, SVGNumberList, SVGPathElement, SVGPatternElement, SVGPointList, SVGPolygonElement, SVGPolylineElement, SVGPreserveAspectRatio, SVGRadialGradientElement, SVGRectElement, SVGSVGElementEventMap, SVGSVGElement, SVGScriptElement, SVGSetElement, SVGStopElement, SVGStringList, SVGStyleElement, SVGSwitchElement, SVGSymbolElement, SVGTSpanElement, SVGTests, SVGTextContentElement, SVGTextElement, SVGTextPathElement, SVGTextPositioningElement, SVGTitleElement, SVGTransform, SVGTransformList, SVGURIReference, SVGUnitTypes, SVGUseElement, SVGViewElement, Screen, ScreenOrientationEventMap, ScreenOrientation, ScriptProcessorNodeEventMap, ScriptProcessorNode, SecurityPolicyViolationEvent, Selection, ServiceWorkerEventMap, ServiceWorker, ServiceWorkerContainerEventMap, ServiceWorkerContainer, ServiceWorkerRegistrationEventMap, ServiceWorkerRegistration, ShadowRootEventMap, ShadowRoot, SharedWorker, Slottable, SourceBufferEventMap, SourceBuffer, SourceBufferListEventMap, SourceBufferList, SpeechRecognitionAlternative, SpeechRecognitionResult, SpeechRecognitionResultList, SpeechSynthesisEventMap, SpeechSynthesis, SpeechSynthesisErrorEvent, SpeechSynthesisEvent, SpeechSynthesisUtteranceEventMap, SpeechSynthesisUtterance, SpeechSynthesisVoice, StaticRange, StereoPannerNode, Storage, StorageEvent, StorageManager, StyleMedia, StylePropertyMap, StylePropertyMapReadOnly, StyleSheet, StyleSheetList, SubmitEvent, SubtleCrypto, Text, TextDecoder, TextDecoderCommon, TextDecoderStream, TextEncoder, TextEncoderCommon, TextEncoderStream, TextEvent, TextMetrics, TextTrackEventMap, TextTrack, TextTrackCueEventMap, TextTrackCue, TextTrackCueList, TextTrackListEventMap, TextTrackList, TimeRanges, ToggleEvent, Touch, TouchEvent, TouchList, TrackEvent, TransformStream, TransformStreamDefaultController, TransitionEvent, TreeWalker, UIEvent, URL, URLSearchParams, UserActivation, VTTCue, VTTRegion, ValidityState, VideoColorSpace, VideoDecoderEventMap, VideoDecoder, VideoEncoderEventMap, VideoEncoder, VideoFrame, VideoPlaybackQuality, ViewTransition, VisualViewportEventMap, VisualViewport, WEBGL_color_buffer_float, WEBGL_compressed_texture_astc, WEBGL_compressed_texture_etc, WEBGL_compressed_texture_etc1, WEBGL_compressed_texture_pvrtc, WEBGL_compressed_texture_s3tc, WEBGL_compressed_texture_s3tc_srgb, WEBGL_debug_renderer_info, WEBGL_debug_shaders, WEBGL_depth_texture, WEBGL_draw_buffers, WEBGL_lose_context, WEBGL_multi_draw, WakeLock, WakeLockSentinelEventMap, WakeLockSentinel, WaveShaperNode, WebGL2RenderingContext, WebGL2RenderingContextBase, WebGL2RenderingContextOverloads, WebGLActiveInfo, WebGLBuffer, WebGLContextEvent, WebGLFramebuffer, WebGLProgram, WebGLQuery, WebGLRenderbuffer, WebGLRenderingContext, WebGLRenderingContextBase, WebGLRenderingContextOverloads, WebGLSampler, WebGLShader, WebGLShaderPrecisionFormat, WebGLSync, WebGLTexture, WebGLTransformFeedback, WebGLUniformLocation, WebGLVertexArrayObject, WebGLVertexArrayObjectOES, WebSocketEventMap, WebSocket, WebTransport, WebTransportBidirectionalStream, WebTransportDatagramDuplexStream, WebTransportError, WheelEvent, WindowEventMap, Window, WindowEventHandlersEventMap, WindowEventHandlers, WindowLocalStorage, WindowOrWorkerGlobalScope, WindowSessionStorage, WorkerEventMap, Worker, Worklet, WritableStream, WritableStreamDefaultController, WritableStreamDefaultWriter, XMLDocument, XMLHttpRequestEventMap, XMLHttpRequest, XMLHttpRequestEventTargetEventMap, XMLHttpRequestEventTarget, XMLHttpRequestUpload, XMLSerializer, XPathEvaluator, XPathEvaluatorBase, XPathExpression, XPathResult, XSLTProcessor, Console, CompileError, Global, Instance, LinkError, Memory, Module, RuntimeError, Table, GlobalDescriptor, MemoryDescriptor, ModuleExportDescriptor, ModuleImportDescriptor, TableDescriptor, ValueTypeMap, WebAssemblyInstantiatedSource, AudioDataOutputCallback, BlobCallback, CustomElementConstructor, DecodeErrorCallback, DecodeSuccessCallback, EncodedAudioChunkOutputCallback, EncodedVideoChunkOutputCallback, ErrorCallback, FileCallback, FileSystemEntriesCallback, FileSystemEntryCallback, FrameRequestCallback, FunctionStringCallback, IdleRequestCallback, IntersectionObserverCallback, LockGrantedCallback, MediaSessionActionHandler, MutationCallback, NotificationPermissionCallback, OnBeforeUnloadEventHandlerNonNull, OnErrorEventHandlerNonNull, PerformanceObserverCallback, PositionCallback, PositionErrorCallback, QueuingStrategySize, RTCPeerConnectionErrorCallback, RTCSessionDescriptionCallback, RemotePlaybackAvailabilityCallback, ReportingObserverCallback, ResizeObserverCallback, TransformerFlushCallback, TransformerStartCallback, TransformerTransformCallback, UnderlyingSinkAbortCallback, UnderlyingSinkCloseCallback, UnderlyingSinkStartCallback, UnderlyingSinkWriteCallback, UnderlyingSourceCancelCallback, UnderlyingSourcePullCallback, UnderlyingSourceStartCallback, VideoFrameOutputCallback, VideoFrameRequestCallback, ViewTransitionUpdateCallback, VoidFunction, WebCodecsErrorCallback, HTMLElementTagNameMap, HTMLElementDeprecatedTagNameMap, SVGElementTagNameMap, MathMLElementTagNameMap
- Classes: 
- Functions: Hz, Q, cap, ch, cm, cqb, cqh, cqi, cqmax, cqmin, cqw, deg, dpcm, dpi, dppx, dvb, dvh, dvi, dvmax, dvmin, dvw, em, escape, ex, fr, grad, ic, kHz, lh, lvb, lvh, lvi, lvmax, lvmin, lvw, mm, ms, number, pc, percent, pt, px, rad, rcap, rch, registerProperty, rem, rex, ric, rlh, s, supports, supports, svb, svh, svi, svmax, svmin, svw, turn, vb, vh, vi, vmax, vmin, vw, compile, compileStreaming, instantiate, instantiate, instantiateStreaming, validate, alert, blur, cancelIdleCallback, captureEvents, close, confirm, focus, getComputedStyle, getSelection, matchMedia, moveBy, moveTo, open, postMessage, postMessage, print, prompt, releaseEvents, requestIdleCallback, resizeBy, resizeTo, scroll, scroll, scrollBy, scrollBy, scrollTo, scrollTo, stop, toString, dispatchEvent, cancelAnimationFrame, requestAnimationFrame, atob, btoa, clearInterval, clearTimeout, createImageBitmap, createImageBitmap, fetch, queueMicrotask, reportError, setInterval, setTimeout, structuredClone, addEventListener, addEventListener, removeEventListener, removeEventListener

### lib.dom.iterable.d.ts
- Imports: 
- Exports: 
- Interfaces: AbortSignal, AudioParam, AudioParamMap, BaseAudioContext, CSSKeyframesRule, CSSNumericArray, CSSRuleList, CSSStyleDeclaration, CSSTransformValue, CSSUnparsedValue, Cache, CanvasPath, CanvasPathDrawingStyles, CustomStateSet, DOMRectList, DOMStringList, DOMTokenList, DataTransferItemList, EventCounts, FileList, FontFaceSet, FormDataIterator, FormData, HTMLAllCollection, HTMLCollectionBase, HTMLCollectionOf, HTMLFormElement, HTMLSelectElement, HeadersIterator, Headers, Highlight, HighlightRegistry, IDBDatabase, IDBObjectStore, MIDIInputMap, MIDIOutput, MIDIOutputMap, MediaKeyStatusMapIterator, MediaKeyStatusMap, MediaList, MessageEvent, MimeTypeArray, NamedNodeMap, Navigator, NodeList, NodeListOf, Plugin, PluginArray, RTCRtpTransceiver, RTCStatsReport, SVGLengthList, SVGNumberList, SVGPointList, SVGStringList, SVGTransformList, SourceBufferList, SpeechRecognitionResult, SpeechRecognitionResultList, StylePropertyMapReadOnlyIterator, StylePropertyMapReadOnly, StyleSheetList, SubtleCrypto, TextTrackCueList, TextTrackList, TouchList, URLSearchParamsIterator, URLSearchParams, WEBGL_draw_buffers, WEBGL_multi_draw, WebGL2RenderingContextBase, WebGL2RenderingContextOverloads, WebGLRenderingContextBase, WebGLRenderingContextOverloads
- Classes: 
- Functions: 

### lib.es2015.collection.d.ts
- Imports: 
- Exports: 
- Interfaces: Map, MapConstructor, ReadonlyMap, WeakMap, WeakMapConstructor, Set, SetConstructor, ReadonlySet, WeakSet, WeakSetConstructor
- Classes: 
- Functions: 

### lib.es2015.core.d.ts
- Imports: 
- Exports: 
- Interfaces: Array, ArrayConstructor, DateConstructor, Function, Math, NumberConstructor, ObjectConstructor, ReadonlyArray, RegExp, RegExpConstructor, String, StringConstructor, Int8Array, Uint8Array, Uint8ClampedArray, Int16Array, Uint16Array, Int32Array, Uint32Array, Float32Array, Float64Array
- Classes: 
- Functions: 

### lib.es2015.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2015.generator.d.ts
- Imports: 
- Exports: 
- Interfaces: Generator, GeneratorFunction, GeneratorFunctionConstructor
- Classes: 
- Functions: 

### lib.es2015.iterable.d.ts
- Imports: 
- Exports: 
- Interfaces: SymbolConstructor, IteratorYieldResult, IteratorReturnResult, Iterator, Iterable, IterableIterator, IteratorObject, ArrayIterator, Array, ArrayConstructor, ReadonlyArray, IArguments, MapIterator, Map, ReadonlyMap, MapConstructor, WeakMap, WeakMapConstructor, SetIterator, Set, ReadonlySet, SetConstructor, WeakSet, WeakSetConstructor, Promise, PromiseConstructor, StringIterator, String, Int8Array, Int8ArrayConstructor, Uint8Array, Uint8ArrayConstructor, Uint8ClampedArray, Uint8ClampedArrayConstructor, Int16Array, Int16ArrayConstructor, Uint16Array, Uint16ArrayConstructor, Int32Array, Int32ArrayConstructor, Uint32Array, Uint32ArrayConstructor, Float32Array, Float32ArrayConstructor, Float64Array, Float64ArrayConstructor
- Classes: 
- Functions: 

### lib.es2015.promise.d.ts
- Imports: 
- Exports: 
- Interfaces: PromiseConstructor
- Classes: 
- Functions: 

### lib.es2015.proxy.d.ts
- Imports: 
- Exports: 
- Interfaces: ProxyHandler, ProxyConstructor
- Classes: 
- Functions: 

### lib.es2015.reflect.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: apply, apply, construct, construct, defineProperty, deleteProperty, get, getOwnPropertyDescriptor, getPrototypeOf, has, isExtensible, ownKeys, preventExtensions, set, set, setPrototypeOf

### lib.es2015.symbol.d.ts
- Imports: 
- Exports: 
- Interfaces: SymbolConstructor
- Classes: 
- Functions: 

### lib.es2015.symbol.wellknown.d.ts
- Imports: 
- Exports: 
- Interfaces: SymbolConstructor, Symbol, Array, ReadonlyArray, Date, Map, WeakMap, Set, WeakSet, JSON, Function, GeneratorFunction, Math, Promise, PromiseConstructor, RegExp, RegExpConstructor, String, ArrayBuffer, DataView, Int8Array, Uint8Array, Uint8ClampedArray, Int16Array, Uint16Array, Int32Array, Uint32Array, Float32Array, Float64Array, ArrayConstructor, MapConstructor, SetConstructor, ArrayBufferConstructor
- Classes: 
- Functions: 

### lib.es2016.array.include.d.ts
- Imports: 
- Exports: 
- Interfaces: Array, ReadonlyArray, Int8Array, Uint8Array, Uint8ClampedArray, Int16Array, Uint16Array, Int32Array, Uint32Array, Float32Array, Float64Array
- Classes: 
- Functions: 

### lib.es2016.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2016.full.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2016.intl.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: getCanonicalLocales

### lib.es2017.arraybuffer.d.ts
- Imports: 
- Exports: 
- Interfaces: ArrayBufferConstructor
- Classes: 
- Functions: 

### lib.es2017.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2017.date.d.ts
- Imports: 
- Exports: 
- Interfaces: DateConstructor
- Classes: 
- Functions: 

### lib.es2017.full.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2017.intl.d.ts
- Imports: 
- Exports: 
- Interfaces: DateTimeFormatPartTypesRegistry, DateTimeFormatPart, DateTimeFormat
- Classes: 
- Functions: 

### lib.es2017.object.d.ts
- Imports: 
- Exports: 
- Interfaces: ObjectConstructor
- Classes: 
- Functions: 

### lib.es2017.sharedmemory.d.ts
- Imports: 
- Exports: 
- Interfaces: SharedArrayBuffer, SharedArrayBufferConstructor, ArrayBufferTypes, Atomics
- Classes: 
- Functions: 

### lib.es2017.string.d.ts
- Imports: 
- Exports: 
- Interfaces: String
- Classes: 
- Functions: 

### lib.es2017.typedarrays.d.ts
- Imports: 
- Exports: 
- Interfaces: Int8ArrayConstructor, Uint8ArrayConstructor, Uint8ClampedArrayConstructor, Int16ArrayConstructor, Uint16ArrayConstructor, Int32ArrayConstructor, Uint32ArrayConstructor, Float32ArrayConstructor, Float64ArrayConstructor
- Classes: 
- Functions: 

### lib.es2018.asyncgenerator.d.ts
- Imports: 
- Exports: 
- Interfaces: AsyncGenerator, AsyncGeneratorFunction, AsyncGeneratorFunctionConstructor
- Classes: 
- Functions: 

### lib.es2018.asynciterable.d.ts
- Imports: 
- Exports: 
- Interfaces: SymbolConstructor, AsyncIterator, AsyncIterable, AsyncIterableIterator, AsyncIteratorObject
- Classes: 
- Functions: 

### lib.es2018.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2018.full.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2018.intl.d.ts
- Imports: 
- Exports: 
- Interfaces: PluralRulesOptions, ResolvedPluralRulesOptions, PluralRules, PluralRulesConstructor, NumberFormatPartTypeRegistry, NumberFormatPart, NumberFormat
- Classes: 
- Functions: 

### lib.es2018.promise.d.ts
- Imports: 
- Exports: 
- Interfaces: Promise
- Classes: 
- Functions: 

### lib.es2018.regexp.d.ts
- Imports: 
- Exports: 
- Interfaces: RegExpMatchArray, RegExpExecArray, RegExp
- Classes: 
- Functions: 

### lib.es2019.array.d.ts
- Imports: 
- Exports: 
- Interfaces: ReadonlyArray, Array
- Classes: 
- Functions: 

### lib.es2019.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2019.full.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2019.intl.d.ts
- Imports: 
- Exports: 
- Interfaces: DateTimeFormatPartTypesRegistry
- Classes: 
- Functions: 

### lib.es2019.object.d.ts
- Imports: 
- Exports: 
- Interfaces: ObjectConstructor
- Classes: 
- Functions: 

### lib.es2019.string.d.ts
- Imports: 
- Exports: 
- Interfaces: String
- Classes: 
- Functions: 

### lib.es2019.symbol.d.ts
- Imports: 
- Exports: 
- Interfaces: Symbol
- Classes: 
- Functions: 

### lib.es2020.bigint.d.ts
- Imports: 
- Exports: 
- Interfaces: BigIntToLocaleStringOptions, BigInt, BigIntConstructor, BigInt64Array, BigInt64ArrayConstructor, BigUint64Array, BigUint64ArrayConstructor, DataView, NumberFormat
- Classes: 
- Functions: 

### lib.es2020.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2020.date.d.ts
- Imports: 
- Exports: 
- Interfaces: Date
- Classes: 
- Functions: 

### lib.es2020.full.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2020.intl.d.ts
- Imports: 
- Exports: 
- Interfaces: RelativeTimeFormatOptions, ResolvedRelativeTimeFormatOptions, RelativeTimeFormat, NumberFormatOptionsStyleRegistry, NumberFormatOptionsCurrencyDisplayRegistry, NumberFormatOptionsSignDisplayRegistry, NumberFormatOptions, ResolvedNumberFormatOptions, NumberFormatPartTypeRegistry, DateTimeFormatOptions, LocaleOptions, Locale, DisplayNamesOptions, ResolvedDisplayNamesOptions, DisplayNames, CollatorConstructor, DateTimeFormatConstructor, NumberFormatConstructor, PluralRulesConstructor
- Classes: 
- Functions: 

### lib.es2020.number.d.ts
- Imports: 
- Exports: 
- Interfaces: Number
- Classes: 
- Functions: 

### lib.es2020.promise.d.ts
- Imports: 
- Exports: 
- Interfaces: PromiseFulfilledResult, PromiseRejectedResult, PromiseConstructor
- Classes: 
- Functions: 

### lib.es2020.sharedmemory.d.ts
- Imports: 
- Exports: 
- Interfaces: Atomics
- Classes: 
- Functions: 

### lib.es2020.string.d.ts
- Imports: 
- Exports: 
- Interfaces: String
- Classes: 
- Functions: 

### lib.es2020.symbol.wellknown.d.ts
- Imports: 
- Exports: 
- Interfaces: SymbolConstructor, RegExpStringIterator, RegExp
- Classes: 
- Functions: 

### lib.es2021.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2021.full.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2021.intl.d.ts
- Imports: 
- Exports: 
- Interfaces: DateTimeFormatPartTypesRegistry, DateTimeFormatOptions, DateTimeRangeFormatPart, DateTimeFormat, ResolvedDateTimeFormatOptions, ListFormatOptions, ResolvedListFormatOptions, ListFormat
- Classes: 
- Functions: 

### lib.es2021.promise.d.ts
- Imports: 
- Exports: 
- Interfaces: AggregateError, AggregateErrorConstructor, PromiseConstructor
- Classes: 
- Functions: 

### lib.es2021.string.d.ts
- Imports: 
- Exports: 
- Interfaces: String
- Classes: 
- Functions: 

### lib.es2021.weakref.d.ts
- Imports: 
- Exports: 
- Interfaces: WeakRef, WeakRefConstructor, FinalizationRegistry, FinalizationRegistryConstructor
- Classes: 
- Functions: 

### lib.es2022.array.d.ts
- Imports: 
- Exports: 
- Interfaces: Array, ReadonlyArray, Int8Array, Uint8Array, Uint8ClampedArray, Int16Array, Uint16Array, Int32Array, Uint32Array, Float32Array, Float64Array, BigInt64Array, BigUint64Array
- Classes: 
- Functions: 

### lib.es2022.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2022.error.d.ts
- Imports: 
- Exports: 
- Interfaces: ErrorOptions, Error, ErrorConstructor, EvalErrorConstructor, RangeErrorConstructor, ReferenceErrorConstructor, SyntaxErrorConstructor, TypeErrorConstructor, URIErrorConstructor, AggregateErrorConstructor
- Classes: 
- Functions: 

### lib.es2022.full.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2022.intl.d.ts
- Imports: 
- Exports: 
- Interfaces: SegmenterOptions, Segmenter, ResolvedSegmenterOptions, SegmentIterator, Segments, SegmentData
- Classes: 
- Functions: supportedValuesOf

### lib.es2022.object.d.ts
- Imports: 
- Exports: 
- Interfaces: ObjectConstructor
- Classes: 
- Functions: 

### lib.es2022.regexp.d.ts
- Imports: 
- Exports: 
- Interfaces: RegExpMatchArray, RegExpExecArray, RegExpIndicesArray, RegExp
- Classes: 
- Functions: 

### lib.es2022.string.d.ts
- Imports: 
- Exports: 
- Interfaces: String
- Classes: 
- Functions: 

### lib.es2023.array.d.ts
- Imports: 
- Exports: 
- Interfaces: Array, ReadonlyArray, Int8Array, Uint8Array, Uint8ClampedArray, Int16Array, Uint16Array, Int32Array, Uint32Array, Float32Array, Float64Array, BigInt64Array, BigUint64Array
- Classes: 
- Functions: 

### lib.es2023.collection.d.ts
- Imports: 
- Exports: 
- Interfaces: WeakKeyTypes
- Classes: 
- Functions: 

### lib.es2023.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2023.full.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2023.intl.d.ts
- Imports: 
- Exports: 
- Interfaces: NumberFormatOptionsUseGroupingRegistry, NumberFormatOptionsSignDisplayRegistry, NumberFormatOptions, ResolvedNumberFormatOptions, NumberRangeFormatPart, NumberFormat
- Classes: 
- Functions: 

### lib.es2024.arraybuffer.d.ts
- Imports: 
- Exports: 
- Interfaces: ArrayBuffer, ArrayBufferConstructor
- Classes: 
- Functions: 

### lib.es2024.collection.d.ts
- Imports: 
- Exports: 
- Interfaces: MapConstructor
- Classes: 
- Functions: 

### lib.es2024.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2024.full.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.es2024.object.d.ts
- Imports: 
- Exports: 
- Interfaces: ObjectConstructor
- Classes: 
- Functions: 

### lib.es2024.promise.d.ts
- Imports: 
- Exports: 
- Interfaces: PromiseWithResolvers, PromiseConstructor
- Classes: 
- Functions: 

### lib.es2024.regexp.d.ts
- Imports: 
- Exports: 
- Interfaces: RegExp
- Classes: 
- Functions: 

### lib.es2024.sharedmemory.d.ts
- Imports: 
- Exports: 
- Interfaces: Atomics, SharedArrayBuffer, SharedArrayBufferConstructor
- Classes: 
- Functions: 

### lib.es2024.string.d.ts
- Imports: 
- Exports: 
- Interfaces: String
- Classes: 
- Functions: 

### lib.es5.d.ts
- Imports: 
- Exports: 
- Interfaces: Symbol, PropertyDescriptor, PropertyDescriptorMap, Object, ObjectConstructor, Function, FunctionConstructor, CallableFunction, NewableFunction, IArguments, String, StringConstructor, Boolean, BooleanConstructor, Number, NumberConstructor, TemplateStringsArray, ImportMeta, ImportCallOptions, ImportAssertions, ImportAttributes, Math, Date, DateConstructor, RegExpMatchArray, RegExpExecArray, RegExp, RegExpConstructor, Error, ErrorConstructor, EvalError, EvalErrorConstructor, RangeError, RangeErrorConstructor, ReferenceError, ReferenceErrorConstructor, SyntaxError, SyntaxErrorConstructor, TypeError, TypeErrorConstructor, URIError, URIErrorConstructor, JSON, ReadonlyArray, ConcatArray, Array, ArrayConstructor, TypedPropertyDescriptor, PromiseLike, Promise, ArrayLike, ThisType, WeakKeyTypes, ArrayBuffer, ArrayBufferTypes, ArrayBufferConstructor, ArrayBufferView, DataView, DataViewConstructor, Int8Array, Int8ArrayConstructor, Uint8Array, Uint8ArrayConstructor, Uint8ClampedArray, Uint8ClampedArrayConstructor, Int16Array, Int16ArrayConstructor, Uint16Array, Uint16ArrayConstructor, Int32Array, Int32ArrayConstructor, Uint32Array, Uint32ArrayConstructor, Float32Array, Float32ArrayConstructor, Float64Array, Float64ArrayConstructor, CollatorOptions, ResolvedCollatorOptions, Collator, CollatorConstructor, NumberFormatOptionsStyleRegistry, NumberFormatOptionsCurrencyDisplayRegistry, NumberFormatOptionsUseGroupingRegistry, NumberFormatOptions, ResolvedNumberFormatOptions, NumberFormat, NumberFormatConstructor, DateTimeFormatOptions, ResolvedDateTimeFormatOptions, DateTimeFormat, DateTimeFormatConstructor, String, Number, Date
- Classes: 
- Functions: eval, parseInt, parseFloat, isNaN, isFinite, decodeURI, decodeURIComponent, encodeURI, encodeURIComponent, escape, unescape

### lib.es6.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.esnext.array.d.ts
- Imports: 
- Exports: 
- Interfaces: ArrayConstructor
- Classes: 
- Functions: 

### lib.esnext.collection.d.ts
- Imports: 
- Exports: 
- Interfaces: ReadonlySetLike, Set, ReadonlySet
- Classes: 
- Functions: 

### lib.esnext.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.esnext.decorators.d.ts
- Imports: 
- Exports: 
- Interfaces: SymbolConstructor, Function
- Classes: 
- Functions: 

### lib.esnext.disposable.d.ts
- Imports: 
- Exports: 
- Interfaces: SymbolConstructor, Disposable, AsyncDisposable, SuppressedError, SuppressedErrorConstructor, DisposableStack, DisposableStackConstructor, AsyncDisposableStack, AsyncDisposableStackConstructor, IteratorObject, AsyncIteratorObject
- Classes: 
- Functions: 

### lib.esnext.full.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.esnext.intl.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### lib.esnext.iterator.d.ts
- Imports: 
- Exports: 
- Interfaces: Iterator, IteratorObject, IteratorConstructor
- Classes: Iterator
- Functions: 

### lib.scripthost.d.ts
- Imports: 
- Exports: 
- Interfaces: ActiveXObject, ITextWriter, TextStreamBase, TextStreamWriter, TextStreamReader, Enumerator, EnumeratorConstructor, VBArray, VBArrayConstructor, DateConstructor, Date
- Classes: SafeArray, VarDate
- Functions: 

### lib.webworker.asynciterable.d.ts
- Imports: 
- Exports: 
- Interfaces: FileSystemDirectoryHandleAsyncIterator, FileSystemDirectoryHandle, ReadableStreamAsyncIterator, ReadableStream
- Classes: 
- Functions: 

### lib.webworker.d.ts
- Imports: 
- Exports: 
- Interfaces: AddEventListenerOptions, AesCbcParams, AesCtrParams, AesDerivedKeyParams, AesGcmParams, AesKeyAlgorithm, AesKeyGenParams, Algorithm, AudioConfiguration, AudioDataCopyToOptions, AudioDataInit, AudioDecoderConfig, AudioDecoderInit, AudioDecoderSupport, AudioEncoderConfig, AudioEncoderInit, AudioEncoderSupport, AvcEncoderConfig, BlobPropertyBag, CSSMatrixComponentOptions, CSSNumericType, CacheQueryOptions, ClientQueryOptions, CloseEventInit, CryptoKeyPair, CustomEventInit, DOMMatrix2DInit, DOMMatrixInit, DOMPointInit, DOMQuadInit, DOMRectInit, EcKeyGenParams, EcKeyImportParams, EcdhKeyDeriveParams, EcdsaParams, EncodedAudioChunkInit, EncodedAudioChunkMetadata, EncodedVideoChunkInit, EncodedVideoChunkMetadata, ErrorEventInit, EventInit, EventListenerOptions, EventSourceInit, ExtendableEventInit, ExtendableMessageEventInit, FetchEventInit, FilePropertyBag, FileSystemCreateWritableOptions, FileSystemGetDirectoryOptions, FileSystemGetFileOptions, FileSystemReadWriteOptions, FileSystemRemoveOptions, FontFaceDescriptors, FontFaceSetLoadEventInit, GetNotificationOptions, HkdfParams, HmacImportParams, HmacKeyGenParams, IDBDatabaseInfo, IDBIndexParameters, IDBObjectStoreParameters, IDBTransactionOptions, IDBVersionChangeEventInit, ImageBitmapOptions, ImageBitmapRenderingContextSettings, ImageDataSettings, ImageEncodeOptions, JsonWebKey, KeyAlgorithm, LockInfo, LockManagerSnapshot, LockOptions, MediaCapabilitiesDecodingInfo, MediaCapabilitiesEncodingInfo, MediaCapabilitiesInfo, MediaConfiguration, MediaDecodingConfiguration, MediaEncodingConfiguration, MediaStreamTrackProcessorInit, MessageEventInit, MultiCacheQueryOptions, NavigationPreloadState, NotificationEventInit, NotificationOptions, OpusEncoderConfig, Pbkdf2Params, PerformanceMarkOptions, PerformanceMeasureOptions, PerformanceObserverInit, PermissionDescriptor, PlaneLayout, ProgressEventInit, PromiseRejectionEventInit, PushEventInit, PushSubscriptionJSON, PushSubscriptionOptionsInit, QueuingStrategy, QueuingStrategyInit, RTCEncodedAudioFrameMetadata, RTCEncodedVideoFrameMetadata, ReadableStreamGetReaderOptions, ReadableStreamIteratorOptions, ReadableStreamReadDoneResult, ReadableStreamReadValueResult, ReadableWritablePair, RegistrationOptions, ReportingObserverOptions, RequestInit, ResponseInit, RsaHashedImportParams, RsaHashedKeyGenParams, RsaKeyGenParams, RsaOaepParams, RsaOtherPrimesInfo, RsaPssParams, SecurityPolicyViolationEventInit, StorageEstimate, StreamPipeOptions, StructuredSerializeOptions, TextDecodeOptions, TextDecoderOptions, TextEncoderEncodeIntoResult, Transformer, UnderlyingByteSource, UnderlyingDefaultSource, UnderlyingSink, UnderlyingSource, VideoColorSpaceInit, VideoConfiguration, VideoDecoderConfig, VideoDecoderInit, VideoDecoderSupport, VideoEncoderConfig, VideoEncoderEncodeOptions, VideoEncoderEncodeOptionsForAvc, VideoEncoderInit, VideoEncoderSupport, VideoFrameBufferInit, VideoFrameCopyToOptions, VideoFrameInit, WebGLContextAttributes, WebGLContextEventInit, WebTransportCloseInfo, WebTransportErrorOptions, WebTransportHash, WebTransportOptions, WebTransportSendStreamOptions, WorkerOptions, WriteParams, ANGLE_instanced_arrays, AbortController, AbortSignalEventMap, AbortSignal, AbstractWorkerEventMap, AbstractWorker, AnimationFrameProvider, AudioData, AudioDecoderEventMap, AudioDecoder, AudioEncoderEventMap, AudioEncoder, Blob, Body, BroadcastChannelEventMap, BroadcastChannel, ByteLengthQueuingStrategy, CSSImageValue, CSSKeywordValue, CSSMathClamp, CSSMathInvert, CSSMathMax, CSSMathMin, CSSMathNegate, CSSMathProduct, CSSMathSum, CSSMathValue, CSSMatrixComponent, CSSNumericArray, CSSNumericValue, CSSPerspective, CSSRotate, CSSScale, CSSSkew, CSSSkewX, CSSSkewY, CSSStyleValue, CSSTransformComponent, CSSTransformValue, CSSTranslate, CSSUnitValue, CSSUnparsedValue, CSSVariableReferenceValue, Cache, CacheStorage, CanvasCompositing, CanvasDrawImage, CanvasDrawPath, CanvasFillStrokeStyles, CanvasFilters, CanvasGradient, CanvasImageData, CanvasImageSmoothing, CanvasPath, CanvasPathDrawingStyles, CanvasPattern, CanvasRect, CanvasShadowStyles, CanvasState, CanvasText, CanvasTextDrawingStyles, CanvasTransform, Client, Clients, CloseEvent, CompressionStream, CountQueuingStrategy, Crypto, CryptoKey, CustomEvent, DOMException, DOMMatrix, DOMMatrixReadOnly, DOMPoint, DOMPointReadOnly, DOMQuad, DOMRect, DOMRectReadOnly, DOMStringList, DecompressionStream, DedicatedWorkerGlobalScopeEventMap, DedicatedWorkerGlobalScope, EXT_blend_minmax, EXT_color_buffer_float, EXT_color_buffer_half_float, EXT_float_blend, EXT_frag_depth, EXT_sRGB, EXT_shader_texture_lod, EXT_texture_compression_bptc, EXT_texture_compression_rgtc, EXT_texture_filter_anisotropic, EXT_texture_norm16, EncodedAudioChunk, EncodedVideoChunk, ErrorEvent, Event, EventListener, EventListenerObject, EventSourceEventMap, EventSource, EventTarget, ExtendableEvent, ExtendableMessageEvent, FetchEvent, File, FileList, FileReaderEventMap, FileReader, FileReaderSync, FileSystemDirectoryHandle, FileSystemFileHandle, FileSystemHandle, FileSystemSyncAccessHandle, FileSystemWritableFileStream, FontFace, FontFaceSetEventMap, FontFaceSet, FontFaceSetLoadEvent, FontFaceSource, FormData, GenericTransformStream, Headers, IDBCursor, IDBCursorWithValue, IDBDatabaseEventMap, IDBDatabase, IDBFactory, IDBIndex, IDBKeyRange, IDBObjectStore, IDBOpenDBRequestEventMap, IDBOpenDBRequest, IDBRequestEventMap, IDBRequest, IDBTransactionEventMap, IDBTransaction, IDBVersionChangeEvent, ImageBitmap, ImageBitmapRenderingContext, ImageData, ImportMeta, KHR_parallel_shader_compile, Lock, LockManager, MediaCapabilities, MediaSourceHandle, MediaStreamTrackProcessor, MessageChannel, MessageEvent, MessagePortEventMap, MessagePort, NavigationPreloadManager, NavigatorBadge, NavigatorConcurrentHardware, NavigatorID, NavigatorLanguage, NavigatorLocks, NavigatorOnLine, NavigatorStorage, NotificationEventMap, Notification, NotificationEvent, OES_draw_buffers_indexed, OES_element_index_uint, OES_fbo_render_mipmap, OES_standard_derivatives, OES_texture_float, OES_texture_float_linear, OES_texture_half_float, OES_texture_half_float_linear, OES_vertex_array_object, OVR_multiview2, OffscreenCanvasEventMap, OffscreenCanvas, OffscreenCanvasRenderingContext2D, Path2D, PerformanceEventMap, Performance, PerformanceEntry, PerformanceMark, PerformanceMeasure, PerformanceObserver, PerformanceObserverEntryList, PerformanceResourceTiming, PerformanceServerTiming, PermissionStatusEventMap, PermissionStatus, Permissions, ProgressEvent, PromiseRejectionEvent, PushEvent, PushManager, PushMessageData, PushSubscription, PushSubscriptionOptions, RTCEncodedAudioFrame, RTCEncodedVideoFrame, RTCRtpScriptTransformer, RTCTransformEvent, ReadableByteStreamController, ReadableStream, ReadableStreamBYOBReader, ReadableStreamBYOBRequest, ReadableStreamDefaultController, ReadableStreamDefaultReader, ReadableStreamGenericReader, Report, ReportBody, ReportingObserver, Request, Response, SecurityPolicyViolationEvent, ServiceWorkerEventMap, ServiceWorker, ServiceWorkerContainerEventMap, ServiceWorkerContainer, ServiceWorkerGlobalScopeEventMap, ServiceWorkerGlobalScope, ServiceWorkerRegistrationEventMap, ServiceWorkerRegistration, SharedWorkerGlobalScopeEventMap, SharedWorkerGlobalScope, StorageManager, StylePropertyMapReadOnly, SubtleCrypto, TextDecoder, TextDecoderCommon, TextDecoderStream, TextEncoder, TextEncoderCommon, TextEncoderStream, TextMetrics, TransformStream, TransformStreamDefaultController, URL, URLSearchParams, VideoColorSpace, VideoDecoderEventMap, VideoDecoder, VideoEncoderEventMap, VideoEncoder, VideoFrame, WEBGL_color_buffer_float, WEBGL_compressed_texture_astc, WEBGL_compressed_texture_etc, WEBGL_compressed_texture_etc1, WEBGL_compressed_texture_pvrtc, WEBGL_compressed_texture_s3tc, WEBGL_compressed_texture_s3tc_srgb, WEBGL_debug_renderer_info, WEBGL_debug_shaders, WEBGL_depth_texture, WEBGL_draw_buffers, WEBGL_lose_context, WEBGL_multi_draw, WebGL2RenderingContext, WebGL2RenderingContextBase, WebGL2RenderingContextOverloads, WebGLActiveInfo, WebGLBuffer, WebGLContextEvent, WebGLFramebuffer, WebGLProgram, WebGLQuery, WebGLRenderbuffer, WebGLRenderingContext, WebGLRenderingContextBase, WebGLRenderingContextOverloads, WebGLSampler, WebGLShader, WebGLShaderPrecisionFormat, WebGLSync, WebGLTexture, WebGLTransformFeedback, WebGLUniformLocation, WebGLVertexArrayObject, WebGLVertexArrayObjectOES, WebSocketEventMap, WebSocket, WebTransport, WebTransportBidirectionalStream, WebTransportDatagramDuplexStream, WebTransportError, WindowClient, WindowOrWorkerGlobalScope, WorkerEventMap, Worker, WorkerGlobalScopeEventMap, WorkerGlobalScope, WorkerLocation, WorkerNavigator, WritableStream, WritableStreamDefaultController, WritableStreamDefaultWriter, XMLHttpRequestEventMap, XMLHttpRequest, XMLHttpRequestEventTargetEventMap, XMLHttpRequestEventTarget, XMLHttpRequestUpload, Console, CompileError, Global, Instance, LinkError, Memory, Module, RuntimeError, Table, GlobalDescriptor, MemoryDescriptor, ModuleExportDescriptor, ModuleImportDescriptor, TableDescriptor, ValueTypeMap, WebAssemblyInstantiatedSource, AudioDataOutputCallback, EncodedAudioChunkOutputCallback, EncodedVideoChunkOutputCallback, FrameRequestCallback, LockGrantedCallback, OnErrorEventHandlerNonNull, PerformanceObserverCallback, QueuingStrategySize, ReportingObserverCallback, TransformerFlushCallback, TransformerStartCallback, TransformerTransformCallback, UnderlyingSinkAbortCallback, UnderlyingSinkCloseCallback, UnderlyingSinkStartCallback, UnderlyingSinkWriteCallback, UnderlyingSourceCancelCallback, UnderlyingSourcePullCallback, UnderlyingSourceStartCallback, VideoFrameOutputCallback, VoidFunction, WebCodecsErrorCallback
- Classes: 
- Functions: compile, compileStreaming, instantiate, instantiate, instantiateStreaming, validate, close, postMessage, postMessage, dispatchEvent, importScripts, dispatchEvent, atob, btoa, clearInterval, clearTimeout, createImageBitmap, createImageBitmap, fetch, queueMicrotask, reportError, setInterval, setTimeout, structuredClone, cancelAnimationFrame, requestAnimationFrame, addEventListener, addEventListener, removeEventListener, removeEventListener

### lib.webworker.importscripts.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: importScripts

### lib.webworker.iterable.d.ts
- Imports: 
- Exports: 
- Interfaces: AbortSignal, CSSNumericArray, CSSTransformValue, CSSUnparsedValue, Cache, CanvasPath, CanvasPathDrawingStyles, DOMStringList, FileList, FontFaceSet, FormDataIterator, FormData, HeadersIterator, Headers, IDBDatabase, IDBObjectStore, MessageEvent, StylePropertyMapReadOnlyIterator, StylePropertyMapReadOnly, SubtleCrypto, URLSearchParamsIterator, URLSearchParams, WEBGL_draw_buffers, WEBGL_multi_draw, WebGL2RenderingContextBase, WebGL2RenderingContextOverloads, WebGLRenderingContextBase, WebGLRenderingContextOverloads
- Classes: 
- Functions: 

### tsserverlibrary.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### typescript.d.ts
- Imports: 
- Exports: 
- Interfaces: Message, Request, ReloadProjectsRequest, Event, Response, PerformanceData, FileDiagnosticPerformanceData, FileRequestArgs, StatusRequest, StatusResponseBody, StatusResponse, DocCommentTemplateRequest, DocCommandTemplateResponse, TodoCommentRequest, TodoCommentRequestArgs, TodoCommentsResponse, SpanOfEnclosingCommentRequest, SpanOfEnclosingCommentRequestArgs, OutliningSpansRequest, OutliningSpansResponse, IndentationRequest, IndentationResponse, IndentationResult, IndentationRequestArgs, ProjectInfoRequestArgs, ProjectInfoRequest, CompilerOptionsDiagnosticsRequest, CompilerOptionsDiagnosticsRequestArgs, DefaultConfiguredProjectInfo, ProjectInfo, DiagnosticWithLinePosition, ProjectInfoResponse, FileRequest, FileLocationRequestArgs, GetApplicableRefactorsRequest, GetApplicableRefactorsResponse, GetMoveToRefactoringFileSuggestionsRequest, GetMoveToRefactoringFileSuggestions, PreparePasteEditsRequest, PreparePasteEditsRequestArgs, PreparePasteEditsResponse, GetPasteEditsRequest, GetPasteEditsRequestArgs, GetPasteEditsResponse, PasteEditsAction, GetEditsForRefactorRequest, GetEditsForRefactorResponse, RefactorEditInfo, OrganizeImportsRequest, OrganizeImportsRequestArgs, OrganizeImportsResponse, GetEditsForFileRenameRequest, GetEditsForFileRenameRequestArgs, GetEditsForFileRenameResponse, CodeFixRequest, GetCombinedCodeFixRequest, GetCombinedCodeFixResponse, ApplyCodeActionCommandRequest, ApplyCodeActionCommandResponse, FileRangeRequestArgs, CodeFixRequestArgs, GetCombinedCodeFixRequestArgs, GetCombinedCodeFixScope, ApplyCodeActionCommandRequestArgs, GetCodeFixesResponse, FileLocationRequest, GetSupportedCodeFixesRequest, GetSupportedCodeFixesResponse, EncodedSemanticClassificationsRequest, EncodedSemanticClassificationsRequestArgs, EncodedSemanticClassificationsResponse, EncodedSemanticClassificationsResponseBody, DocumentHighlightsRequestArgs, DefinitionRequest, DefinitionAndBoundSpanRequest, FindSourceDefinitionRequest, DefinitionAndBoundSpanResponse, TypeDefinitionRequest, ImplementationRequest, Location, TextSpan, FileSpan, JSDocTagInfo, TextSpanWithContext, FileSpanWithContext, DefinitionInfo, DefinitionInfoAndBoundSpan, DefinitionResponse, DefinitionInfoAndBoundSpanResponse, TypeDefinitionResponse, ImplementationResponse, BraceCompletionRequest, BraceCompletionRequestArgs, JsxClosingTagRequest, JsxClosingTagRequestArgs, JsxClosingTagResponse, LinkedEditingRangeRequest, LinkedEditingRangesBody, LinkedEditingRangeResponse, DocumentHighlightsRequest, HighlightSpan, DocumentHighlightsItem, DocumentHighlightsResponse, ReferencesRequest, ReferencesResponseItem, ReferencesResponseBody, ReferencesResponse, FileReferencesRequest, FileReferencesResponseBody, FileReferencesResponse, RenameRequestArgs, RenameRequest, SpanGroup, RenameTextSpan, RenameResponseBody, RenameResponse, ExternalFile, ExternalProject, CompileOnSaveMixin, FileWithProjectReferenceRedirectInfo, ProjectChanges, ConfigureRequestArguments, WatchOptions, ConfigureRequest, ConfigureResponse, ConfigurePluginRequestArguments, ConfigurePluginRequest, ConfigurePluginResponse, SelectionRangeRequest, SelectionRangeRequestArgs, SelectionRangeResponse, SelectionRange, ToggleLineCommentRequest, ToggleMultilineCommentRequest, CommentSelectionRequest, UncommentSelectionRequest, OpenRequestArgs, OpenRequest, OpenExternalProjectRequest, OpenExternalProjectsRequest, OpenExternalProjectsArgs, OpenExternalProjectResponse, OpenExternalProjectsResponse, CloseExternalProjectRequest, CloseExternalProjectRequestArgs, CloseExternalProjectResponse, UpdateOpenRequest, UpdateOpenRequestArgs, SetCompilerOptionsForInferredProjectsRequest, SetCompilerOptionsForInferredProjectsArgs, SetCompilerOptionsForInferredProjectsResponse, ExitRequest, CloseRequest, WatchChangeRequest, WatchChangeRequestArgs, CompileOnSaveAffectedFileListRequest, CompileOnSaveAffectedFileListSingleProject, CompileOnSaveAffectedFileListResponse, CompileOnSaveEmitFileRequest, CompileOnSaveEmitFileRequestArgs, CompileOnSaveEmitFileResponse, EmitResult, QuickInfoRequest, QuickInfoResponseBody, QuickInfoResponse, FormatRequestArgs, FormatRequest, CodeEdit, FileCodeEdits, CodeFixResponse, CodeAction, CombinedCodeActions, CodeFixAction, FormatResponse, FormatOnKeyRequestArgs, FormatOnKeyRequest, CompletionsRequestArgs, CompletionsRequest, CompletionDetailsRequestArgs, CompletionEntryIdentifier, CompletionDetailsRequest, JSDocLinkDisplayPart, CompletionsResponse, CompletionInfoResponse, CompletionDetailsResponse, SignatureHelpItems, SignatureHelpRequestArgs, SignatureHelpRequest, SignatureHelpResponse, InlayHintsRequestArgs, InlayHintsRequest, InlayHintItemDisplayPart, InlayHintsResponse, MapCodeRequestArgs, MapCodeRequestDocumentMapping, MapCodeRequest, MapCodeResponse, SemanticDiagnosticsSyncRequest, SemanticDiagnosticsSyncRequestArgs, SemanticDiagnosticsSyncResponse, SuggestionDiagnosticsSyncRequest, SyntacticDiagnosticsSyncRequest, SyntacticDiagnosticsSyncRequestArgs, SyntacticDiagnosticsSyncResponse, GeterrForProjectRequestArgs, GeterrForProjectRequest, GeterrRequestArgs, GeterrRequest, FileRange, FileRangesRequestArgs, RequestCompletedEvent, RequestCompletedEventBody, Diagnostic, DiagnosticWithFileName, DiagnosticRelatedInformation, DiagnosticEventBody, DiagnosticEvent, ConfigFileDiagnosticEventBody, ConfigFileDiagnosticEvent, ProjectLanguageServiceStateEvent, ProjectLanguageServiceStateEventBody, ProjectsUpdatedInBackgroundEvent, ProjectsUpdatedInBackgroundEventBody, ProjectLoadingStartEvent, ProjectLoadingStartEventBody, ProjectLoadingFinishEvent, ProjectLoadingFinishEventBody, SurveyReadyEvent, SurveyReadyEventBody, LargeFileReferencedEvent, LargeFileReferencedEventBody, CreateFileWatcherEvent, CreateFileWatcherEventBody, CreateDirectoryWatcherEvent, CreateDirectoryWatcherEventBody, CloseFileWatcherEvent, CloseFileWatcherEventBody, ReloadRequestArgs, ReloadRequest, ReloadResponse, SavetoRequestArgs, SavetoRequest, NavtoRequestArgs, NavtoRequest, NavtoItem, NavtoResponse, ChangeRequestArgs, ChangeRequest, BraceResponse, BraceRequest, NavBarRequest, NavTreeRequest, NavigationBarItem, NavigationTree, TelemetryEvent, TelemetryEventBody, TypesInstallerInitializationFailedEvent, TypesInstallerInitializationFailedEventBody, TypingsInstalledTelemetryEventBody, TypingsInstalledTelemetryEventPayload, BeginInstallTypesEvent, EndInstallTypesEvent, InstallTypesEventBody, BeginInstallTypesEventBody, EndInstallTypesEventBody, NavBarResponse, NavTreeResponse, CallHierarchyIncomingCall, CallHierarchyOutgoingCall, PrepareCallHierarchyRequest, PrepareCallHierarchyResponse, ProvideCallHierarchyIncomingCallsRequest, ProvideCallHierarchyIncomingCallsResponse, ProvideCallHierarchyOutgoingCallsRequest, ProvideCallHierarchyOutgoingCallsResponse, Log, PendingRequest, TypingInstallerResponse, TypingInstallerRequestWithProjectName, DiscoverTypings, CloseProject, TypesRegistryRequest, InstallPackageRequest, PackageInstalledResponse, InitializationFailedResponse, ProjectResponse, InvalidateCachedTypings, InstallTypes, BeginInstallTypes, EndInstallTypes, InstallTypingHost, SetTypings, WatchTypingLocations, CompressedData, ServerHost, InstallPackageOptionsWithProject, ITypingsInstaller, Logger, NormalizedPathMap, PluginCreateInfo, PluginModule, PluginModuleWithName, ProjectsUpdatedInBackgroundEvent, ProjectLoadingStartEvent, ProjectLoadingFinishEvent, LargeFileReferencedEvent, ConfigFileDiagEvent, ProjectLanguageServiceStateEvent, ProjectInfoTelemetryEvent, OpenFileInfoTelemetryEvent, CreateFileWatcherEvent, CreateDirectoryWatcherEvent, CloseFileWatcherEvent, ProjectInfoTelemetryEventData, OpenFileInfoTelemetryEventData, ProjectInfoTypeAcquisitionData, FileStats, OpenFileInfo, SafeList, TypesMapFile, HostConfiguration, OpenConfiguredProjectResult, ProjectServiceOptions, WatchOptionsAndErrors, ServerCancellationToken, EventSender, SessionOptions, HandlerResponse, TypingResolutionHost, MapLike, SortedReadonlyArray, SortedArray, TextRange, ReadonlyTextRange, Node, Node, JSDocContainer, LocalsContainer, FlowContainer, NodeArray, Token, PunctuationToken, KeywordToken, ModifierToken, Identifier, Identifier, TransientIdentifier, QualifiedName, Declaration, NamedDeclaration, DeclarationStatement, ComputedPropertyName, PrivateIdentifier, PrivateIdentifier, Decorator, TypeParameterDeclaration, SignatureDeclarationBase, CallSignatureDeclaration, ConstructSignatureDeclaration, VariableDeclaration, VariableDeclarationList, ParameterDeclaration, BindingElement, PropertySignature, PropertyDeclaration, AutoAccessorPropertyDeclaration, ObjectLiteralElement, PropertyAssignment, ShorthandPropertyAssignment, SpreadAssignment, ObjectBindingPattern, ArrayBindingPattern, FunctionLikeDeclarationBase, FunctionDeclaration, MethodSignature, MethodDeclaration, ConstructorDeclaration, SemicolonClassElement, GetAccessorDeclaration, SetAccessorDeclaration, IndexSignatureDeclaration, ClassStaticBlockDeclaration, TypeNode, KeywordTypeNode, ImportTypeAssertionContainer, ImportTypeNode, ThisTypeNode, FunctionOrConstructorTypeNodeBase, FunctionTypeNode, ConstructorTypeNode, NodeWithTypeArguments, TypeReferenceNode, TypePredicateNode, TypeQueryNode, TypeLiteralNode, ArrayTypeNode, TupleTypeNode, NamedTupleMember, OptionalTypeNode, RestTypeNode, UnionTypeNode, IntersectionTypeNode, ConditionalTypeNode, InferTypeNode, ParenthesizedTypeNode, TypeOperatorNode, IndexedAccessTypeNode, MappedTypeNode, LiteralTypeNode, StringLiteral, TemplateLiteralTypeNode, TemplateLiteralTypeSpan, Expression, OmittedExpression, PartiallyEmittedExpression, UnaryExpression, UpdateExpression, PrefixUnaryExpression, PostfixUnaryExpression, LeftHandSideExpression, MemberExpression, PrimaryExpression, NullLiteral, TrueLiteral, FalseLiteral, ThisExpression, SuperExpression, ImportExpression, DeleteExpression, TypeOfExpression, VoidExpression, AwaitExpression, YieldExpression, SyntheticExpression, BinaryExpression, AssignmentExpression, ObjectDestructuringAssignment, ArrayDestructuringAssignment, ConditionalExpression, FunctionExpression, ArrowFunction, LiteralLikeNode, TemplateLiteralLikeNode, LiteralExpression, RegularExpressionLiteral, NoSubstitutionTemplateLiteral, NumericLiteral, BigIntLiteral, TemplateHead, TemplateMiddle, TemplateTail, TemplateExpression, TemplateSpan, ParenthesizedExpression, ArrayLiteralExpression, SpreadElement, ObjectLiteralExpressionBase, ObjectLiteralExpression, PropertyAccessExpression, PropertyAccessChain, SuperPropertyAccessExpression, PropertyAccessEntityNameExpression, ElementAccessExpression, ElementAccessChain, SuperElementAccessExpression, CallExpression, CallChain, SuperCall, ImportCall, ExpressionWithTypeArguments, NewExpression, TaggedTemplateExpression, InstanceofExpression, AsExpression, TypeAssertion, SatisfiesExpression, NonNullExpression, NonNullChain, MetaProperty, JsxElement, JsxTagNamePropertyAccess, JsxAttributes, JsxNamespacedName, JsxOpeningElement, JsxSelfClosingElement, JsxFragment, JsxOpeningFragment, JsxClosingFragment, JsxAttribute, JsxSpreadAttribute, JsxClosingElement, JsxExpression, JsxText, Statement, NotEmittedStatement, NotEmittedTypeElement, CommaListExpression, EmptyStatement, DebuggerStatement, MissingDeclaration, Block, VariableStatement, ExpressionStatement, IfStatement, IterationStatement, DoStatement, WhileStatement, ForStatement, ForInStatement, ForOfStatement, BreakStatement, ContinueStatement, ReturnStatement, WithStatement, SwitchStatement, CaseBlock, CaseClause, DefaultClause, LabeledStatement, ThrowStatement, TryStatement, CatchClause, ClassLikeDeclarationBase, ClassDeclaration, ClassExpression, ClassElement, TypeElement, InterfaceDeclaration, HeritageClause, TypeAliasDeclaration, EnumMember, EnumDeclaration, ModuleDeclaration, NamespaceDeclaration, JSDocNamespaceDeclaration, ModuleBlock, ImportEqualsDeclaration, ExternalModuleReference, ImportDeclaration, ImportClause, AssertEntry, AssertClause, ImportAttribute, ImportAttributes, NamespaceImport, NamespaceExport, NamespaceExportDeclaration, ExportDeclaration, NamedImports, NamedExports, ImportSpecifier, ExportSpecifier, ExportAssignment, FileReference, CheckJsDirective, CommentRange, SynthesizedComment, JSDocTypeExpression, JSDocNameReference, JSDocMemberName, JSDocType, JSDocAllType, JSDocUnknownType, JSDocNonNullableType, JSDocNullableType, JSDocOptionalType, JSDocFunctionType, JSDocVariadicType, JSDocNamepathType, JSDoc, JSDocTag, JSDocLink, JSDocLinkCode, JSDocLinkPlain, JSDocText, JSDocUnknownTag, JSDocAugmentsTag, JSDocImplementsTag, JSDocAuthorTag, JSDocDeprecatedTag, JSDocClassTag, JSDocPublicTag, JSDocPrivateTag, JSDocProtectedTag, JSDocReadonlyTag, JSDocOverrideTag, JSDocEnumTag, JSDocThisTag, JSDocTemplateTag, JSDocSeeTag, JSDocReturnTag, JSDocTypeTag, JSDocTypedefTag, JSDocCallbackTag, JSDocOverloadTag, JSDocThrowsTag, JSDocSignature, JSDocPropertyLikeTag, JSDocPropertyTag, JSDocParameterTag, JSDocTypeLiteral, JSDocSatisfiesTag, JSDocImportTag, IncompleteType, AmdDependency, SourceFileLike, SourceFileLike, SourceFile, SourceFile, Bundle, JsonSourceFile, TsConfigSourceFile, JsonMinusNumericLiteral, JsonObjectExpressionStatement, ScriptReferenceHost, ParseConfigHost, WriteFileCallbackData, CancellationToken, Program, ResolvedProjectReference, CustomTransformer, CustomTransformers, SourceMapSpan, EmitResult, TypeChecker, TypePredicateBase, ThisTypePredicate, IdentifierTypePredicate, AssertsThisTypePredicate, AssertsIdentifierTypePredicate, Symbol, Symbol, Type, Type, FreshableType, LiteralType, UniqueESSymbolType, StringLiteralType, NumberLiteralType, BigIntLiteralType, EnumType, ObjectType, InterfaceType, InterfaceTypeWithDeclaredMembers, TypeReference, TypeReference, DeferredTypeReference, GenericType, TupleType, TupleTypeReference, UnionOrIntersectionType, UnionType, IntersectionType, EvolvingArrayType, InstantiableType, TypeParameter, IndexedAccessType, IndexType, ConditionalRoot, ConditionalType, TemplateLiteralType, StringMappingType, SubstitutionType, Signature, Signature, IndexInfo, FileExtensionInfo, DiagnosticMessage, DiagnosticMessageChain, Diagnostic, DiagnosticRelatedInformation, DiagnosticWithLocation, PluginImport, ProjectReference, CompilerOptions, WatchOptions, TypeAcquisition, LineAndCharacter, ParsedCommandLine, CreateProgramOptions, ModuleResolutionHost, MinimalResolutionCacheHost, ResolvedModule, ResolvedModuleFull, PackageId, ResolvedModuleWithFailedLookupLocations, ResolvedTypeReferenceDirective, ResolvedTypeReferenceDirectiveWithFailedLookupLocations, CompilerHost, SourceMapRange, SourceMapSource, SourceMapSource, EmitHelperBase, ScopedEmitHelper, UnscopedEmitHelper, NodeFactory, CoreTransformationContext, TransformationContext, TransformationResult, NodeVisitor, NodesVisitor, Printer, PrintHandlers, PrinterOptions, GetEffectiveTypeRootsHost, TextSpan, TextChangeRange, SyntaxList, UserPreferences, PseudoBigInt, System, FileWatcher, Scanner, CreateSourceFileOptions, ParsedBuildCommand, ConfigFileDiagnosticsReporter, ParseConfigFileHost, ParsedTsconfig, ExtendedConfigCacheEntry, TypeReferenceDirectiveResolutionCache, ModeAwareCache, PerDirectoryResolutionCache, NonRelativeNameResolutionCache, PerNonRelativeNameCache, ModuleResolutionCache, NonRelativeModuleNameResolutionCache, PackageJsonInfoCache, FormatDiagnosticsHost, EmitOutput, OutputFile, BuilderProgramHost, BuilderProgram, SemanticDiagnosticsBuilderProgram, EmitAndSemanticDiagnosticsBuilderProgram, ReadBuildProgramHost, IncrementalProgramOptions, WatchHost, ProgramHost, WatchCompilerHost, WatchCompilerHostOfFilesAndCompilerOptions, WatchCompilerHostOfConfigFile, Watch, WatchOfConfigFile, WatchOfFilesAndCompilerOptions, BuildOptions, ReportFileInError, SolutionBuilderHostBase, SolutionBuilderHost, SolutionBuilderWithWatchHost, SolutionBuilder, InvalidatedProjectBase, UpdateOutputFileStampsProject, BuildInvalidedProject, IScriptSnapshot, PreProcessedFileInfo, HostCancellationToken, InstallPackageOptions, PerformanceEvent, IncompleteCompletionsCache, LanguageServiceHost, LanguageService, JsxClosingTagInfo, LinkedEditingInfo, CombinedCodeFixScope, PasteEdits, PasteEditsArgs, OrganizeImportsArgs, GetCompletionsAtPositionOptions, SignatureHelpItemsOptions, SignatureHelpInvokedReason, SignatureHelpCharacterTypedReason, SignatureHelpRetriggeredReason, ApplyCodeActionCommandResult, Classifications, ClassifiedSpan, ClassifiedSpan2020, NavigationBarItem, NavigationTree, CallHierarchyItem, CallHierarchyIncomingCall, CallHierarchyOutgoingCall, InlayHint, InlayHintDisplayPart, TodoCommentDescriptor, TodoComment, TextChange, FileTextChanges, CodeAction, CodeFixAction, CombinedCodeActions, InstallPackageAction, ApplicableRefactorInfo, RefactorActionInfo, RefactorEditInfo, TextInsertion, DocumentSpan, RenameLocation, ReferenceEntry, ImplementationLocation, HighlightSpan, NavigateToItem, EditorOptions, EditorSettings, FormatCodeOptions, FormatCodeSettings, DefinitionInfo, DefinitionInfoAndBoundSpan, ReferencedSymbolDefinitionInfo, ReferencedSymbol, ReferencedSymbolEntry, SymbolDisplayPart, JSDocLinkDisplayPart, JSDocTagInfo, QuickInfo, RenameInfoSuccess, RenameInfoFailure, RenameInfoOptions, DocCommentTemplateOptions, InteractiveRefactorArguments, SignatureHelpParameter, SelectionRange, SignatureHelpItem, SignatureHelpItems, CompletionInfo, CompletionEntryDataAutoImport, CompletionEntryDataUnresolved, CompletionEntryDataResolved, CompletionEntry, CompletionEntryLabelDetails, CompletionEntryDetails, OutliningSpan, ClassificationResult, ClassificationInfo, Classifier, InlayHintsContext, DocumentHighlights, DocumentRegistry, TranspileOptions, TranspileOutput
- Classes: TypingsInstaller, ScriptInfo, Project, InferredProject, AutoImportProviderProject, ConfiguredProject, ExternalProject, ProjectService, Session, OperationCanceledException
- Functions: createInstallTypingsRequest, toNormalizedPath, normalizedPathToPath, asNormalizedPath, createNormalizedPathMap, isInferredProjectName, makeInferredProjectName, createSortedArray, ThrowNoProject, ThrowProjectLanguageServiceDisabled, ThrowProjectDoesNotContainDocument, isDynamicFileName, allRootFilesAreJsOrDts, allFilesAreJsOrDts, convertFormatOptions, convertCompilerOptions, convertWatchOptions, convertTypeAcquisition, tryConvertScriptKindName, convertScriptKindName, formatMessage, tokenToString, getPositionOfLineAndCharacter, getLineAndCharacterOfPosition, isWhiteSpaceLike, isWhiteSpaceSingleLine, isLineBreak, couldStartTrivia, forEachLeadingCommentRange, forEachLeadingCommentRange, forEachTrailingCommentRange, forEachTrailingCommentRange, reduceEachLeadingCommentRange, reduceEachTrailingCommentRange, getLeadingCommentRanges, getTrailingCommentRanges, getShebang, isIdentifierStart, isIdentifierPart, createScanner, isExternalModuleNameRelative, sortAndDeduplicateDiagnostics, getDefaultLibFileName, textSpanEnd, textSpanIsEmpty, textSpanContainsPosition, textSpanContainsTextSpan, textSpanOverlapsWith, textSpanOverlap, textSpanIntersectsWithTextSpan, textSpanIntersectsWith, decodedTextSpanIntersectsWith, textSpanIntersectsWithPosition, textSpanIntersection, createTextSpan, createTextSpanFromBounds, textChangeRangeNewSpan, textChangeRangeIsUnchanged, createTextChangeRange, collapseTextChangeRangesAcrossMultipleVersions, getTypeParameterOwner, isParameterPropertyDeclaration, isEmptyBindingPattern, isEmptyBindingElement, walkUpBindingElementsAndPatterns, getCombinedModifierFlags, getCombinedNodeFlags, validateLocaleAndSetLanguage, getOriginalNode, getOriginalNode, getOriginalNode, getOriginalNode, findAncestor, findAncestor, isParseTreeNode, getParseTreeNode, getParseTreeNode, escapeLeadingUnderscores, unescapeLeadingUnderscores, idText, identifierToKeywordKind, symbolName, getNameOfJSDocTypedef, getNameOfDeclaration, getDecorators, getModifiers, getJSDocParameterTags, getJSDocTypeParameterTags, hasJSDocParameterTags, getJSDocAugmentsTag, getJSDocImplementsTags, getJSDocClassTag, getJSDocPublicTag, getJSDocPrivateTag, getJSDocProtectedTag, getJSDocReadonlyTag, getJSDocOverrideTagNoCache, getJSDocDeprecatedTag, getJSDocEnumTag, getJSDocThisTag, getJSDocReturnTag, getJSDocTemplateTag, getJSDocSatisfiesTag, getJSDocTypeTag, getJSDocType, getJSDocReturnType, getJSDocTags, getAllJSDocTags, getAllJSDocTagsOfKind, getTextOfJSDocComment, getEffectiveTypeParameterDeclarations, getEffectiveConstraintOfTypeParameter, isMemberName, isPropertyAccessChain, isElementAccessChain, isCallChain, isOptionalChain, isNullishCoalesce, isConstTypeReference, skipPartiallyEmittedExpressions, skipPartiallyEmittedExpressions, isNonNullChain, isBreakOrContinueStatement, isNamedExportBindings, isJSDocPropertyLikeTag, isTokenKind, isToken, isLiteralExpression, isTemplateLiteralToken, isTemplateMiddleOrTemplateTail, isImportOrExportSpecifier, isTypeOnlyImportDeclaration, isTypeOnlyExportDeclaration, isTypeOnlyImportOrExportDeclaration, isPartOfTypeOnlyImportOrExportDeclaration, isStringTextContainingNode, isImportAttributeName, isModifier, isEntityName, isPropertyName, isBindingName, isFunctionLike, isClassElement, isClassLike, isAccessor, isAutoAccessorPropertyDeclaration, isModifierLike, isTypeElement, isClassOrTypeElement, isObjectLiteralElementLike, isTypeNode, isFunctionOrConstructorTypeNode, isArrayBindingElement, isPropertyAccessOrQualifiedName, isCallLikeExpression, isCallOrNewExpression, isTemplateLiteral, isLeftHandSideExpression, isLiteralTypeLiteral, isExpression, isAssertionExpression, isIterationStatement, isIterationStatement, isConciseBody, isForInitializer, isModuleBody, isNamedImportBindings, isDeclarationStatement, isStatement, isModuleReference, isJsxTagNameExpression, isJsxChild, isJsxAttributeLike, isStringLiteralOrJsxExpression, isJsxOpeningLikeElement, isJsxCallLike, isCaseOrDefaultClause, isJSDocCommentContainingNode, isSetAccessor, isGetAccessor, hasOnlyExpressionInitializer, isObjectLiteralElement, isStringLiteralLike, isJSDocLinkLike, hasRestParameter, isRestParameter, isInternalDeclaration, isPartOfTypeNode, getJSDocCommentsAndTags, createSourceMapSource, setOriginalNode, disposeEmitNodes, setEmitFlags, getSourceMapRange, setSourceMapRange, getTokenSourceMapRange, setTokenSourceMapRange, getCommentRange, setCommentRange, getSyntheticLeadingComments, setSyntheticLeadingComments, addSyntheticLeadingComment, getSyntheticTrailingComments, setSyntheticTrailingComments, addSyntheticTrailingComment, moveSyntheticComments, getConstantValue, setConstantValue, addEmitHelper, addEmitHelpers, removeEmitHelper, getEmitHelpers, moveEmitHelpers, isNumericLiteral, isBigIntLiteral, isStringLiteral, isJsxText, isRegularExpressionLiteral, isNoSubstitutionTemplateLiteral, isTemplateHead, isTemplateMiddle, isTemplateTail, isDotDotDotToken, isPlusToken, isMinusToken, isAsteriskToken, isExclamationToken, isQuestionToken, isColonToken, isQuestionDotToken, isEqualsGreaterThanToken, isIdentifier, isPrivateIdentifier, isAssertsKeyword, isAwaitKeyword, isQualifiedName, isComputedPropertyName, isTypeParameterDeclaration, isParameter, isDecorator, isPropertySignature, isPropertyDeclaration, isMethodSignature, isMethodDeclaration, isClassStaticBlockDeclaration, isConstructorDeclaration, isGetAccessorDeclaration, isSetAccessorDeclaration, isCallSignatureDeclaration, isConstructSignatureDeclaration, isIndexSignatureDeclaration, isTypePredicateNode, isTypeReferenceNode, isFunctionTypeNode, isConstructorTypeNode, isTypeQueryNode, isTypeLiteralNode, isArrayTypeNode, isTupleTypeNode, isNamedTupleMember, isOptionalTypeNode, isRestTypeNode, isUnionTypeNode, isIntersectionTypeNode, isConditionalTypeNode, isInferTypeNode, isParenthesizedTypeNode, isThisTypeNode, isTypeOperatorNode, isIndexedAccessTypeNode, isMappedTypeNode, isLiteralTypeNode, isImportTypeNode, isTemplateLiteralTypeSpan, isTemplateLiteralTypeNode, isObjectBindingPattern, isArrayBindingPattern, isBindingElement, isArrayLiteralExpression, isObjectLiteralExpression, isPropertyAccessExpression, isElementAccessExpression, isCallExpression, isNewExpression, isTaggedTemplateExpression, isTypeAssertionExpression, isParenthesizedExpression, isFunctionExpression, isArrowFunction, isDeleteExpression, isTypeOfExpression, isVoidExpression, isAwaitExpression, isPrefixUnaryExpression, isPostfixUnaryExpression, isBinaryExpression, isConditionalExpression, isTemplateExpression, isYieldExpression, isSpreadElement, isClassExpression, isOmittedExpression, isExpressionWithTypeArguments, isAsExpression, isSatisfiesExpression, isNonNullExpression, isMetaProperty, isSyntheticExpression, isPartiallyEmittedExpression, isCommaListExpression, isTemplateSpan, isSemicolonClassElement, isBlock, isVariableStatement, isEmptyStatement, isExpressionStatement, isIfStatement, isDoStatement, isWhileStatement, isForStatement, isForInStatement, isForOfStatement, isContinueStatement, isBreakStatement, isReturnStatement, isWithStatement, isSwitchStatement, isLabeledStatement, isThrowStatement, isTryStatement, isDebuggerStatement, isVariableDeclaration, isVariableDeclarationList, isFunctionDeclaration, isClassDeclaration, isInterfaceDeclaration, isTypeAliasDeclaration, isEnumDeclaration, isModuleDeclaration, isModuleBlock, isCaseBlock, isNamespaceExportDeclaration, isImportEqualsDeclaration, isImportDeclaration, isImportClause, isImportTypeAssertionContainer, isAssertClause, isAssertEntry, isImportAttributes, isImportAttribute, isNamespaceImport, isNamespaceExport, isNamedImports, isImportSpecifier, isExportAssignment, isExportDeclaration, isNamedExports, isExportSpecifier, isModuleExportName, isMissingDeclaration, isNotEmittedStatement, isExternalModuleReference, isJsxElement, isJsxSelfClosingElement, isJsxOpeningElement, isJsxClosingElement, isJsxFragment, isJsxOpeningFragment, isJsxClosingFragment, isJsxAttribute, isJsxAttributes, isJsxSpreadAttribute, isJsxExpression, isJsxNamespacedName, isCaseClause, isDefaultClause, isHeritageClause, isCatchClause, isPropertyAssignment, isShorthandPropertyAssignment, isSpreadAssignment, isEnumMember, isSourceFile, isBundle, isJSDocTypeExpression, isJSDocNameReference, isJSDocMemberName, isJSDocLink, isJSDocLinkCode, isJSDocLinkPlain, isJSDocAllType, isJSDocUnknownType, isJSDocNullableType, isJSDocNonNullableType, isJSDocOptionalType, isJSDocFunctionType, isJSDocVariadicType, isJSDocNamepathType, isJSDoc, isJSDocTypeLiteral, isJSDocSignature, isJSDocAugmentsTag, isJSDocAuthorTag, isJSDocClassTag, isJSDocCallbackTag, isJSDocPublicTag, isJSDocPrivateTag, isJSDocProtectedTag, isJSDocReadonlyTag, isJSDocOverrideTag, isJSDocOverloadTag, isJSDocDeprecatedTag, isJSDocSeeTag, isJSDocEnumTag, isJSDocParameterTag, isJSDocReturnTag, isJSDocThisTag, isJSDocTypeTag, isJSDocTemplateTag, isJSDocTypedefTag, isJSDocUnknownTag, isJSDocPropertyTag, isJSDocImplementsTag, isJSDocSatisfiesTag, isJSDocThrowsTag, isJSDocImportTag, isQuestionOrExclamationToken, isIdentifierOrThisTypeNode, isReadonlyKeywordOrPlusOrMinusToken, isQuestionOrPlusOrMinusToken, isModuleName, isBinaryOperatorToken, setTextRange, canHaveModifiers, canHaveDecorators, forEachChild, createSourceFile, parseIsolatedEntityName, parseJsonText, isExternalModule, updateSourceFile, parseCommandLine, parseBuildCommand, getParsedCommandLineOfConfigFile, readConfigFile, parseConfigFileTextToJson, readJsonConfigFile, convertToObject, parseJsonConfigFileContent, parseJsonSourceFileConfigFileContent, convertCompilerOptionsFromJson, convertTypeAcquisitionFromJson, getEffectiveTypeRoots, resolveTypeReferenceDirective, getAutomaticTypeDirectiveNames, createModuleResolutionCache, createTypeReferenceDirectiveResolutionCache, resolveModuleNameFromCache, resolveModuleName, bundlerModuleNameResolver, nodeModuleNameResolver, classicNameResolver, visitNode, visitNode, visitNodes, visitNodes, visitLexicalEnvironment, visitParameterList, visitParameterList, visitFunctionBody, visitFunctionBody, visitFunctionBody, visitIterationBody, visitCommaListElements, visitEachChild, visitEachChild, getTsBuildInfoEmitOutputFilePath, getOutputFileNames, createPrinter, findConfigFile, resolveTripleslashReference, createCompilerHost, getPreEmitDiagnostics, formatDiagnostics, formatDiagnostic, formatDiagnosticsWithColorAndContext, flattenDiagnosticMessageText, getModeForFileReference, getModeForResolutionAtIndex, getModeForUsageLocation, getConfigFileParsingDiagnostics, getImpliedNodeFormatForFile, createProgram, createProgram, resolveProjectReferencePath, createSemanticDiagnosticsBuilderProgram, createSemanticDiagnosticsBuilderProgram, createEmitAndSemanticDiagnosticsBuilderProgram, createEmitAndSemanticDiagnosticsBuilderProgram, createAbstractBuilder, createAbstractBuilder, readBuilderProgram, createIncrementalCompilerHost, createIncrementalProgram, createWatchCompilerHost, createWatchCompilerHost, createWatchProgram, createWatchProgram, createBuilderStatusReporter, createSolutionBuilderHost, createSolutionBuilderWithWatchHost, createSolutionBuilder, createSolutionBuilderWithWatch, isBuildCommand, getDefaultFormatCodeSettings, fromString, createClassifier, createDocumentRegistry, preProcessFile, transpileModule, transpileDeclaration, transpile, toEditorSettings, displayPartsToString, getDefaultCompilerOptions, getSupportedCodeFixes, createLanguageServiceSourceFile, updateLanguageServiceSourceFile, createLanguageService, getDefaultLibFilePath, transform

### agent.d.ts
- Imports: url, ./pool, ./dispatcher
- Exports: 
- Interfaces: Options, DispatchOptions
- Classes: Agent
- Functions: 

### api.d.ts
- Imports: url, stream, ./dispatcher
- Exports: 
- Interfaces: 
- Classes: 
- Functions: request, stream, pipeline, connect, upgrade

### balanced-pool.d.ts
- Imports: ./pool, ./dispatcher, url
- Exports: 
- Interfaces: 
- Classes: BalancedPool
- Functions: 

### cache.d.ts
- Imports: ./fetch
- Exports: 
- Interfaces: CacheStorage, Cache, CacheQueryOptions, MultiCacheQueryOptions
- Classes: 
- Functions: 

### client.d.ts
- Imports: url, tls, ./dispatcher, ./connector
- Exports: 
- Interfaces: OptionsInterceptors, Options, SocketInfo
- Classes: Client
- Functions: 

### connector.d.ts
- Imports: tls, net
- Exports: 
- Interfaces: Options, connector
- Classes: 
- Functions: buildConnector

### content-type.d.ts
- Imports: 
- Exports: 
- Interfaces: MIMEType
- Classes: 
- Functions: parseMIMEType, serializeAMimeType

### cookies.d.ts
- Imports: ./fetch
- Exports: 
- Interfaces: Cookie
- Classes: 
- Functions: deleteCookie, getCookies, getSetCookies, setCookie

### diagnostics-channel.d.ts
- Imports: net, url, ./connector, ./dispatcher
- Exports: 
- Interfaces: Request, Response, ConnectParams, RequestCreateMessage, RequestBodySentMessage, RequestHeadersMessage, RequestTrailersMessage, RequestErrorMessage, ClientSendHeadersMessage, ClientBeforeConnectMessage, ClientConnectedMessage, ClientConnectErrorMessage
- Classes: 
- Functions: 

### dispatcher.d.ts
- Imports: url, stream, events, buffer, ./header, ./readable, ./formdata, ./errors
- Exports: 
- Interfaces: ComposedDispatcher, DispatchOptions, ConnectOptions, RequestOptions, PipelineOptions, UpgradeOptions, ConnectData, ResponseData, PipelineHandlerData, StreamData, UpgradeData, StreamFactoryData, DispatchHandlers, BodyMixin, DispatchInterceptor
- Classes: Dispatcher
- Functions: 

### env-http-proxy-agent.d.ts
- Imports: ./agent, ./dispatcher
- Exports: 
- Interfaces: Options
- Classes: EnvHttpProxyAgent
- Functions: 

### errors.d.ts
- Imports: ./header, ./client
- Exports: 
- Interfaces: 
- Classes: UndiciError, ConnectTimeoutError, HeadersTimeoutError, HeadersOverflowError, BodyTimeoutError, ResponseStatusCodeError, InvalidArgumentError, InvalidReturnValueError, RequestAbortedError, InformationalError, RequestContentLengthMismatchError, ResponseContentLengthMismatchError, ClientDestroyedError, ClientClosedError, SocketError, NotSupportedError, BalancedPoolMissingUpstreamError, HTTPParserError, ResponseExceededMaxSizeError, RequestRetryError, SecureProxyConnectionError
- Functions: 

### eventsource.d.ts
- Imports: ./websocket, ./dispatcher, ./patch
- Exports: 
- Interfaces: EventSourceEventMap, EventSource, EventSourceInit
- Classes: 
- Functions: 

### fetch.d.ts
- Imports: buffer, url, stream/web, ./formdata, ./dispatcher
- Exports: 
- Interfaces: SpecIterator, SpecIterableIterator, SpecIterable, RequestInit, ResponseInit
- Classes: BodyMixin, Headers, Request, Response
- Functions: fetch

### file.d.ts
- Imports: buffer
- Exports: 
- Interfaces: BlobPropertyBag, FilePropertyBag
- Classes: File
- Functions: 

### filereader.d.ts
- Imports: buffer, ./patch
- Exports: 
- Interfaces: ProgressEventInit
- Classes: FileReader, ProgressEvent
- Functions: 

### formdata.d.ts
- Imports: ./file, ./fetch
- Exports: 
- Interfaces: 
- Classes: FormData
- Functions: 

### global-dispatcher.d.ts
- Imports: ./dispatcher
- Exports: 
- Interfaces: 
- Classes: 
- Functions: setGlobalDispatcher, getGlobalDispatcher

### global-origin.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: setGlobalOrigin, getGlobalOrigin

### handlers.d.ts
- Imports: ./dispatcher
- Exports: 
- Interfaces: 
- Classes: RedirectHandler, DecoratorHandler
- Functions: 

### header.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: 

### index.d.ts
- Imports: ./dispatcher, ./global-dispatcher, ./global-origin, ./pool, ./handlers, ./balanced-pool, ./client, ./connector, ./errors, ./agent, ./mock-client, ./mock-pool, ./mock-agent, ./mock-errors, ./proxy-agent, ./env-http-proxy-agent, ./retry-handler, ./retry-agent, ./api, ./interceptors
- Exports: ./util, ./cookies, ./eventsource, ./fetch, ./file, ./filereader, ./formdata, ./diagnostics-channel, ./websocket, ./content-type, ./cache, ./mock-interceptor
- Interfaces: 
- Classes: 
- Functions: 

### interceptors.d.ts
- Imports: ./dispatcher, ./retry-handler
- Exports: 
- Interfaces: 
- Classes: 
- Functions: createRedirectInterceptor, dump, retry, redirect, responseError

### mock-agent.d.ts
- Imports: ./agent, ./dispatcher, ./mock-interceptor
- Exports: 
- Interfaces: PendingInterceptor, PendingInterceptorsFormatter, Options
- Classes: MockAgent
- Functions: 

### mock-client.d.ts
- Imports: ./client, ./dispatcher, ./mock-agent, ./mock-interceptor
- Exports: 
- Interfaces: Options
- Classes: MockClient
- Functions: 

### mock-errors.d.ts
- Imports: ./errors
- Exports: 
- Interfaces: 
- Classes: MockNotMatchedError
- Functions: 

### mock-interceptor.d.ts
- Imports: ./header, ./dispatcher, ./fetch
- Exports: 
- Interfaces: Options, MockDispatch, MockDispatchData, MockResponseOptions, MockResponseCallbackOptions, Interceptable
- Classes: MockScope, MockInterceptor
- Functions: 

### mock-pool.d.ts
- Imports: ./pool, ./mock-agent, ./mock-interceptor, ./dispatcher
- Exports: 
- Interfaces: Options
- Classes: MockPool
- Functions: 

### patch.d.ts
- Imports: 
- Exports: 
- Interfaces: EventInit, EventListenerOptions, AddEventListenerOptions, EventListenerObject, EventListener
- Classes: 
- Functions: 

### pool-stats.d.ts
- Imports: ./pool
- Exports: 
- Interfaces: 
- Classes: PoolStats
- Functions: 

### pool.d.ts
- Imports: ./client, ./pool-stats, url, ./dispatcher
- Exports: 
- Interfaces: Options
- Classes: Pool
- Functions: 

### proxy-agent.d.ts
- Imports: ./agent, ./connector, ./dispatcher, ./header
- Exports: 
- Interfaces: Options
- Classes: ProxyAgent
- Functions: 

### readable.d.ts
- Imports: stream, buffer
- Exports: 
- Interfaces: 
- Classes: BodyReadable
- Functions: 

### retry-agent.d.ts
- Imports: ./dispatcher, ./retry-handler
- Exports: 
- Interfaces: 
- Classes: RetryAgent
- Functions: 

### retry-handler.d.ts
- Imports: ./dispatcher
- Exports: 
- Interfaces: RetryOptions, RetryHandlers
- Classes: RetryHandler
- Functions: 

### util.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: headerNameToString, parseHeaders

### webidl.d.ts
- Imports: 
- Exports: 
- Interfaces: ConvertToIntOpts, WebidlErrors, WebidlUtil, WebidlConverters, Webidl
- Classes: 
- Functions: 

### websocket.d.ts
- Imports: buffer, worker_threads, ./patch, ./dispatcher, ./fetch
- Exports: 
- Interfaces: WebSocketEventMap, WebSocket, CloseEventInit, CloseEvent, MessageEventInit, MessageEvent, ErrorEventInit, ErrorEvent, WebSocketInit
- Classes: 
- Functions: 

### v8-compile-cache.d.ts
- Imports: 
- Exports: 
- Interfaces: 
- Classes: 
- Functions: install

### index.d.ts
- Imports: 
- Exports: 
- Interfaces: Options, OptionsWithDefault
- Classes: 
- Functions: 
