// From https://github.com/stephenwvickers/node-net-snmp.
// Copyright 2013 Stephen Vickers <stephen.vickers.sv@gmail.com>
// Very heavily modified by aroth@miovision.
// It only resembles node-net-snmp now. All snmp PDUs other than get & set have been
// stripped out, and the asn1 library has been inlined. All references to Node APIs have been removed,
// and dgram has been replaced with a delegate interface to facilitate use in a browser.
// It was also wrapped in an Angular factory object, to make integrating it into web-apps easier.
(function() {
    'use strict';

    angular
        .module('nodenetsnmp', [])
        .factory('nodenetsnmp', nodenetsnmp);

    function nodenetsnmp() {
        /*****************************************************************************
         ** Constants
         **/

        function _expandConstantObject (object) {
            var keys = [];
            for (var key in object)
                keys.push (key);
            for (var i = 0; i < keys.length; i++)
                object[object[keys[i]]] = parseInt (keys[i]);
        }

        var ErrorStatus = {
            0: "NoError",
            1: "TooBig",
            2: "NoSuchName",
            3: "BadValue",
            4: "ReadOnly",
            5: "GeneralError",
            6: "NoAccess",
            7: "WrongType",
            8: "WrongLength",
            9: "WrongEncoding",
            10: "WrongValue",
            11: "NoCreation",
            12: "InconsistentValue",
            13: "ResourceUnavailable",
            14: "CommitFailed",
            15: "UndoFailed",
            16: "AuthorizationError",
            17: "NotWritable",
            18: "InconsistentName"
        };

        _expandConstantObject (ErrorStatus);

        var ObjectType = {
            1: "Boolean",
            2: "Integer",
            4: "OctetString",
            5: "Null",
            6: "OID",
            64: "IpAddress",
            65: "Counter",
            66: "Gauge",
            67: "TimeTicks",
            68: "Opaque",
            70: "Counter64",
            128: "NoSuchObject",
            129: "NoSuchInstance",
            130: "EndOfMibView"
        };

        _expandConstantObject (ObjectType);

        ObjectType.Integer32 = ObjectType.Integer;
        ObjectType.Counter32 = ObjectType.Counter;
        ObjectType.Gauge32 = ObjectType.Gauge;
        ObjectType.Unsigned32 = ObjectType.Gauge32;

        var PduType = {
            160: "GetRequest",
            161: "GetNextRequest",
            162: "GetResponse",
            163: "SetRequest",
            164: "Trap",
            165: "GetBulkRequest",
            166: "InformRequest",
            167: "TrapV2",
            168: "Report"
        };

        _expandConstantObject (PduType);

        var TrapType = {
            0: "ColdStart",
            1: "WarmStart",
            2: "LinkDown",
            3: "LinkUp",
            4: "AuthenticationFailure",
            5: "EgpNeighborLoss",
            6: "EnterpriseSpecific"
        };

        _expandConstantObject (TrapType);

        var Version1 = 0;

        /*****************************************************************************
         ** Exception class definitions
         **/

        function ResponseInvalidError (message) {
            this.name = "ResponseInvalidError";
            this.message = message;
        }

        function RequestInvalidError (message) {
            this.name = "RequestInvalidError";
            this.message = message;
        }

        function RequestFailedError (message, status) {
            this.name = "RequestFailedError";
            this.message = message;
            this.status = status;
        }

        function RequestTimedOutError (message) {
            this.name = "RequestTimedOutError";
            this.message = message;
        }

        /*****************************************************************************
         ** OID and varbind helper functions
         **/

        function isVarbindError (varbind) {
            return !!(varbind.type == ObjectType.NoSuchObject
            || varbind.type == ObjectType.NoSuchInstance
            || varbind.type == ObjectType.EndOfMibView);
        }

        function varbindError (varbind) {
            return (ObjectType[varbind.type] || "NotAnError") + ": " + varbind.oid;
        }

        function oidFollowsOid (oidString, nextString) {
            var oid = {str: oidString, len: oidString.length, idx: 0};
            var next = {str: nextString, len: nextString.length, idx: 0};
            var dotCharCode = ".".charCodeAt (0);

            function getNumber (item) {
                var n = 0;
                if (item.idx >= item.len)
                    return null;
                while (item.idx < item.len) {
                    var charCode = item.str.charCodeAt (item.idx++);
                    if (charCode == dotCharCode)
                        return n;
                    n = (n ? (n * 10) : n) + (charCode - 48);
                }
                return n;
            }

            while (1) {
                var oidNumber = getNumber (oid);
                var nextNumber = getNumber (next);

                if (oidNumber !== null) {
                    if (nextNumber !== null) {
                        if (nextNumber > oidNumber) {
                            return true;
                        } else if (nextNumber < oidNumber) {
                            return false;
                        }
                    } else {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }

        function oidInSubtree (oidString, nextString) {
            var oid = oidString.split (".");
            var next = nextString.split (".");

            if (oid.length > next.length)
                return false;

            for (var i = 0; i < oid.length; i++) {
                if (next[i] != oid[i])
                    return false;
            }

            return true;
        }

        /**
         * Utility functions
         */

        function _inherits(ctor, superCtor) {
          ctor.super_ = superCtor;
          ctor.prototype = Object.create(superCtor.prototype, {
            constructor: {
              value: ctor,
              enumerable: false,
              writable: true,
              configurable: true
            }
          });
        };

        /**
         ** Some SNMP agents produce integers on the wire such as 00 ff ff ff ff.
         ** The ASN.1 BER parser we use throws an error when parsing this, which we
         ** believe is correct.  So, we decided not to bother the "asn1" developer(s)
         ** with this, instead opting to work around it here.
         **
         ** If an integer is 5 bytes in length we check if the first byte is 0, and if so
         ** simply drop it and parse it like it was a 4 byte integer, otherwise throw
         ** an error since the integer is too large.
         **/

        function readInt (buffer) {
            return readUint (buffer, true);
        }

        function readUint (buffer, isSigned) {
            buffer.readByte ();
            var length = buffer.readByte ();
            var value = 0;
            var signedBitSet = false;

            if (length > 5) {
                 throw new RangeError ("Integer too long '" + length + "'");
            } else if (length == 5) {
                if (buffer.readByte () !== 0)
                    throw new RangeError ("Integer too long '" + length + "'");
                length = 4;
            }

            for (var i = 0; i < length; i++) {
                value *= 256;
                value += buffer.readByte ();

                if (isSigned && i <= 0) {
                    if ((value & 0x80) == 0x80)
                        signedBitSet = true;
                }
            }

            if (signedBitSet)
                value -= (1 << (i * 8));

            return value;
        }

        function readVarbinds (buffer, varbinds) {
            buffer.readSequence ();

            while (1) {
                buffer.readSequence ();
                var oid = buffer.readOID ();
                var type = buffer.peek ();

                if (type == null)
                    break;

                var value;

                if (type == ObjectType.Boolean) {
                    value = buffer.readBoolean ();
                } else if (type == ObjectType.Integer) {
                    value = readInt (buffer);
                } else if (type == ObjectType.OctetString) {
                    value = buffer.readString (null, true);
                } else if (type == ObjectType.Null) {
                    buffer.readByte ();
                    buffer.readByte ();
                    value = null;
                } else if (type == ObjectType.OID) {
                    value = buffer.readOID ();
                } else if (type == ObjectType.NoSuchObject) {
                    buffer.readByte ();
                    buffer.readByte ();
                    value = null;
                } else if (type == ObjectType.NoSuchInstance) {
                    buffer.readByte ();
                    buffer.readByte ();
                    value = null;
                } else if (type == ObjectType.EndOfMibView) {
                    buffer.readByte ();
                    buffer.readByte ();
                    value = null;
                } else {
                    throw new ResponseInvalidError ("Unknown type '" + type
                            + "' in response");
                }

                varbinds.push ({
                    oid: oid,
                    type: type,
                    value: value
                });
            }
        }

        function writeVarbinds (buffer, varbinds) {
            buffer.startSequence ();
            for (var i = 0; i < varbinds.length; i++) {
                buffer.startSequence ();
                buffer.writeOID (varbinds[i].oid);

                if (varbinds[i].type && varbinds[i].hasOwnProperty("value")) {
                    var type = varbinds[i].type;
                    var value = varbinds[i].value;

                    if (type == ObjectType.Boolean) {
                        buffer.writeBoolean (value ? true : false);
                    } else if (type == ObjectType.Integer) { // also Integer32
                        buffer.writeInt (value);
                    } else if (type == ObjectType.OctetString) {
                        if (typeof value == "string")
                            buffer.writeString (value);
                        else {
                            console.log('writingBuffer');
                            buffer.writeBuffer (value, ObjectType.OctetString);
                        }
                    } else if (type == ObjectType.Null) {
                        buffer.writeNull ();
                    } else if (type == ObjectType.OID) {
                        buffer.writeOID (value);
                    } else {
                        throw new RequestInvalidError ("Unknown type '" + type
                                + "' in request");
                    }
                } else {
                    buffer.writeNull ();
                }

                buffer.endSequence ();
            }
            buffer.endSequence ();
        }

        /*****************************************************************************
         ** PDU class definitions
         **/

        var SimplePdu = function (id, varbinds, options) {
            this.id = id;
            this.varbinds = varbinds;
            this.options = options || {};
        };

        SimplePdu.prototype.toBuffer = function (buffer) {
            buffer.startSequence (this.type);

            buffer.writeInt (this.id);
            buffer.writeInt (0);
            buffer.writeInt (0);

            writeVarbinds (buffer, this.varbinds);

            buffer.endSequence ();
        };

        var GetResponsePdu = function (buffer) {
            this.type = PduType.GetResponse;

            buffer.readSequence (this.type);

            this.id = buffer.readInt ();

            this.errorStatus = buffer.readInt ();
            this.errorIndex = buffer.readInt ();

            this.varbinds = [];

            readVarbinds (buffer, this.varbinds);
        };

        var GetRequestPdu = function () {
            this.type = PduType.GetRequest;
            GetRequestPdu.super_.apply (this, arguments);
        };

        _inherits (GetRequestPdu, SimplePdu);

        var InformRequestPdu = function () {
            this.type = PduType.InformRequest;
            InformRequestPdu.super_.apply (this, arguments);
        };

        _inherits (InformRequestPdu, SimplePdu);

        var SetRequestPdu = function () {
            this.type = PduType.SetRequest;
            SetRequestPdu.super_.apply (this, arguments);
        };

        _inherits (SetRequestPdu, SimplePdu);


        /*****************************************************************************
         ** Message class definitions
         **/

        var RequestMessage = function (version, community, pdu) {
            this.version = version;
            this.community = community;
            this.pdu = pdu;
        };

        RequestMessage.prototype.toBuffer = function () {
            if (this.buffer)
                return this.buffer;

            var writer = new ber.Writer ();

            writer.startSequence ();

            writer.writeInt (this.version);
            writer.writeString (this.community);

            this.pdu.toBuffer (writer);

            writer.endSequence ();

            this.buffer = writer.buffer;

            return this.buffer;
        };

        var ResponseMessage = function (buffer) {
            var reader = new ber.Reader (buffer);

            reader.readSequence ();

            this.version = reader.readInt ();
            this.community = reader.readString ();

            var type = reader.peek ();

            if (type == PduType.GetResponse) {
                this.pdu = new GetResponsePdu (reader);
            } else {
                throw new ResponseInvalidError ("Unknown PDU type '" + type
                        + "' in response");
            }
        };

        /*****************************************************************************
         ** Session class definition
         **/

        //Delegate is expected to handle sending for this class.
        // It will have send() called on it, with normal nodejs params, but with a Uint8Array instead of a buffer.
        var Session = function (target, community, options, delegate) {
            this.target = target || "127.0.0.1";
            this.community = community || "public";

            this.version = (options && options.version)
                    ? options.version
                    : Version1;

            this.transport = (options && options.transport)
                    ? options.transport
                    : "udp4";
            this.port = (options && options.port )
                    ? options.port
                    : 161;
            this.trapPort = (options && options.trapPort )
                    ? options.trapPort
                    : 162;

            this.retries = (options && (options.retries || options.retries == 0))
                    ? options.retries
                    : 1;
            this.timeout = (options && options.timeout)
                    ? options.timeout
                    : 5000;

            this.sourceAddress = (options && options.sourceAddress )
                    ? options.sourceAddress
                    : undefined;
            this.sourcePort = (options && options.sourcePort )
                    ? parseInt(options.sourcePort)
                    : undefined;

            this.reqs = {};
            this.reqCount = 0;

            this.dgram = delegate;
            console.log(delegate);
        };

        Session.prototype.close = function () {
            return this;
        };

        Session.prototype.cancelRequests = function (error) {
            var id;
            for (id in this.reqs) {
                var req = this.reqs[id];
                this.unregisterRequest (req.id);
                req.responseCb (error);
            }
        };

        function _generateId () {
            return Math.floor (Math.random () + Math.random () * 10000000)
        }

        Session.prototype.get = function (oids, responseCb) {
            function feedCb (req, message) {
                var pdu = message.pdu;
                var varbinds = [];

                if (req.message.pdu.varbinds.length != pdu.varbinds.length) {
                    req.responseCb (new ResponseInvalidError ("Requested OIDs do not "
                            + "match response OIDs"));
                } else {
                    for (var i = 0; i < req.message.pdu.varbinds.length; i++) {
                        if (req.message.pdu.varbinds[i].oid != pdu.varbinds[i].oid) {
                            req.responseCb (new ResponseInvalidError ("OID '"
                                    + req.message.pdu.varbinds[i].oid
                                    + "' in request at positiion '" + i + "' does not "
                                    + "match OID '" + pdu.varbinds[i].oid + "' in response "
                                    + "at position '" + i + "'"));
                            return;
                        } else {
                            varbinds.push (pdu.varbinds[i]);
                        }
                    }

                    req.responseCb (null, varbinds);
                }
            }

            var pduVarbinds = [];

            for (var i = 0; i < oids.length; i++) {
                var varbind = {
                    oid: oids[i]
                };
                pduVarbinds.push (varbind);
            }

            this.simpleGet (GetRequestPdu, feedCb, pduVarbinds, responseCb);

            return this;
        };

        Session.prototype.onMsg = function (buffer, remote) {
            try {
                var message = new ResponseMessage (buffer);

                var req = this.unregisterRequest (message.pdu.id);
                if (! req)
                    return;

                try {
                    if (message.version != req.message.version) {
                        req.responseCb (new ResponseInvalidError ("Version in request '"
                                + req.message.version + "' does not match version in "
                                + "response '" + message.version));
                    } else if (message.community != req.message.community) {
                        req.responseCb (new ResponseInvalidError ("Community '"
                                + req.message.community + "' in request does not match "
                                + "community '" + message.community + "' in response"));
                    } else if (message.pdu.type == PduType.GetResponse) {
                        req.onResponse (req, message);
                    } else {
                        req.responseCb (new ResponseInvalidError ("Unknown PDU type '"
                                + message.pdu.type + "' in response"));
                    }
                } catch (error) {
                    req.responseCb (error);
                }
            } catch (error) {
                this.emit("error", error);
            }
        };

        Session.prototype.onSimpleGetResponse = function (req, message) {
            var pdu = message.pdu;

            if (pdu.errorStatus > 0) {
                var statusString = ErrorStatus[pdu.errorStatus]
                        || ErrorStatus.GeneralError;
                var statusCode = ErrorStatus[statusString]
                        || ErrorStatus[ErrorStatus.GeneralError];

                if (pdu.errorIndex <= 0 || pdu.errorIndex > pdu.varbinds.length) {
                    req.responseCb (new RequestFailedError (statusString, statusCode));
                } else {
                    var oid = pdu.varbinds[pdu.errorIndex - 1].oid;
                    var error = new RequestFailedError (statusString + ": " + oid,
                            statusCode);
                    req.responseCb (error);
                }
            } else {
                req.feedCb (req, message);
            }
        };

        Session.prototype.registerRequest = function (req) {
            if (! this.reqs[req.id]) {
                this.reqs[req.id] = req;
                this.reqCount++;
            }
            var me = this;
            req.timer = setTimeout (function () {
                if (req.retries-- > 0) {
                    me.send (req);
                } else {
                    me.unregisterRequest (req.id);
                    req.responseCb (new RequestTimedOutError (
                            "Request timed out"));
                }
            }, req.timeout);
        };

        Session.prototype.send = function (req, noWait) {
            try {
                var me = this;

                var buffer = req.message.toBuffer ();

                this.dgram.send (buffer, 0, buffer.length, req.port, this.target,
                        function (error, bytes) {
                    if (error) {
                        req.responseCb (error);
                    } else {
                        if (noWait) {
                            req.responseCb (null);
                        } else {
                            me.registerRequest (req);
                        }
                    }
                });
            } catch (error) {
                req.responseCb (error);
            }

            return this;
        };

        Session.prototype.set = function (varbinds, responseCb) {
            function feedCb (req, message) {
                var pdu = message.pdu;
                var varbinds = [];

                if (req.message.pdu.varbinds.length != pdu.varbinds.length) {
                    req.responseCb (new ResponseInvalidError ("Requested OIDs do not "
                            + "match response OIDs"));
                } else {
                    for (var i = 0; i < req.message.pdu.varbinds.length; i++) {
                        if (req.message.pdu.varbinds[i].oid != pdu.varbinds[i].oid) {
                            req.responseCb (new ResponseInvalidError ("OID '"
                                    + req.message.pdu.varbinds[i].oid
                                    + "' in request at positiion '" + i + "' does not "
                                    + "match OID '" + pdu.varbinds[i].oid + "' in response "
                                    + "at position '" + i + "'"));
                            return;
                        } else {
                            varbinds.push (pdu.varbinds[i]);
                        }
                    }

                    req.responseCb (null, varbinds);
                }
            }

            var pduVarbinds = [];

            for (var i = 0; i < varbinds.length; i++) {
                var varbind = {
                    oid: varbinds[i].oid,
                    type: varbinds[i].type,
                    value: varbinds[i].value
                };
                pduVarbinds.push (varbind);
            }

            this.simpleGet (SetRequestPdu, feedCb, pduVarbinds, responseCb);

            return this;
        };

        Session.prototype.simpleGet = function (pduClass, feedCb, varbinds,
                responseCb, options) {
            var req = {};

            try {
                var id = _generateId ();
                var pdu = new pduClass (id, varbinds, options);
                var message = new RequestMessage (this.version, this.community, pdu);

                req = {
                    id: id,
                    message: message,
                    responseCb: responseCb,
                    retries: this.retries,
                    timeout: this.timeout,
                    onResponse: this.onSimpleGetResponse,
                    feedCb: feedCb,
                    port: (options && options.port) ? options.port : this.port
                };

                this.send (req);
            } catch (error) {
                if (req.responseCb)
                    req.responseCb (error);
            }
        };



        Session.prototype.unregisterRequest = function (id) {
            var req = this.reqs[id];
            if (req) {
                delete this.reqs[id];
                clearTimeout (req.timer);
                delete req.timer;
                this.reqCount--;
                return req;
            } else {
                return null;
            }
        };

        /*****************************************************************************
         ** Exports
         **/
        /*
        exports.Session = Session;

        exports.createSession = function (target, community, options, delegate) {
            return new Session (target, community, options, delegate);
        };

        exports.isVarbindError = isVarbindError;
        exports.varbindError = varbindError;

        exports.Version1 = Version1;

        exports.ErrorStatus = ErrorStatus;
        exports.TrapType = TrapType;
        exports.ObjectType = ObjectType;

        exports.ResponseInvalidError = ResponseInvalidError;
        exports.RequestInvalidError = RequestInvalidError;
        exports.RequestFailedError = RequestFailedError;
        exports.RequestTimedOutError = RequestTimedOutError;
        */

        /**
         * ASN.1 BER I/O. Adapted from node-asn1-ber: all Buffer references removed and replaced with Uint8Arrays.
         *
         * Under MIT license from https://github.com/stephenwvickers/node-asn1-ber.
         *
         * Copyright (c) 2017 Stephen Vickers stephen.vickers.sv@gmail.com
         * Copyright (c) 2011 Mark Cavage mcavage@gmail.com
         */

        var errors = {
            InvalidAsn1Error: function(msg) {
                var e = new Error();
                e.name = 'InvalidAsn1Error';
                e.message = msg || '';
                return e;
            }
        };

        var ASN1 = {
            EOC: 0,
            Boolean: 1,
            Integer: 2,
            BitString: 3,
            OctetString: 4,
            Null: 5,
            OID: 6,
            ObjectDescriptor: 7,
            External: 8,
            Real: 9,
            Enumeration: 10,
            PDV: 11,
            Utf8String: 12,
            RelativeOID: 13,
            Sequence: 16,
            Set: 17,
            NumericString: 18,
            PrintableString: 19,
            T61String: 20,
            VideotexString: 21,
            IA5String: 22,
            UTCTime: 23,
            GeneralizedTime: 24,
            GraphicString: 25,
            VisibleString: 26,
            GeneralString: 28,
            UniversalString: 29,
            CharacterString: 30,
            BMPString: 31,
            Constructor: 32,
            Context: 128
        };

        ///--- Globals
        var InvalidAsn1Error = errors.InvalidAsn1Error;

        var DEFAULT_OPTS = {
            size: 1024,
            growthFactor: 8
        };


        ///--- Helpers

        function merge(from, to) {

            var keys = Object.getOwnPropertyNames(from);
            keys.forEach(function(key) {
                if (to[key])
                    return;

                var value = Object.getOwnPropertyDescriptor(from, key);
                Object.defineProperty(to, key, value);
            });

            return to;
        }

        ///--- API

        function Writer(options) {
            options = merge(DEFAULT_OPTS, options || {});

            this._buf = new Uint8Array(options.size || 1024);
            this._size = this._buf.length;
            this._offset = 0;
            this._options = options;

            // A list of offsets in the buffer where we need to insert
            // sequence tag/len pairs.
            this._seq = [];
        }

        Object.defineProperty(Writer.prototype, 'buffer', {
            get: function () {
                if (this._seq.length)
                    throw new InvalidAsn1Error(this._seq.length + ' unended sequence(s)');

                return (this._buf.slice(0, this._offset));
            }
        });

        Writer.prototype.writeByte = function(b) {
            if (typeof(b) !== 'number')
                throw new TypeError('argument must be a Number');

            this._ensure(1);
            this._buf[this._offset++] = b;
        };


        Writer.prototype.writeInt = function(i, tag) {
            if (typeof(i) !== 'number')
                throw new TypeError('argument must be a Number');
            if (typeof(tag) !== 'number')
                tag = ASN1.Integer;

            var sz = 4;

            while ((((i & 0xff800000) === 0) || ((i & 0xff800000) === 0xff800000 >> 0)) &&
                         (sz > 1)) {
                sz--;
                i <<= 8;
            }

            if (sz > 4)
                throw new InvalidAsn1Error('BER ints cannot be > 0xffffffff');

            this._ensure(2 + sz);
            this._buf[this._offset++] = tag;
            this._buf[this._offset++] = sz;

            while (sz-- > 0) {
                this._buf[this._offset++] = ((i & 0xff000000) >>> 24);
                i <<= 8;
            }

        };


        Writer.prototype.writeNull = function() {
            this.writeByte(ASN1.Null);
            this.writeByte(0x00);
        };


        Writer.prototype.writeEnumeration = function(i, tag) {
            if (typeof(i) !== 'number')
                throw new TypeError('argument must be a Number');
            if (typeof(tag) !== 'number')
                tag = ASN1.Enumeration;

            return this.writeInt(i, tag);
        };


        Writer.prototype.writeBoolean = function(b, tag) {
            if (typeof(b) !== 'boolean')
                throw new TypeError('argument must be a Boolean');
            if (typeof(tag) !== 'number')
                tag = ASN1.Boolean;

            this._ensure(3);
            this._buf[this._offset++] = tag;
            this._buf[this._offset++] = 0x01;
            this._buf[this._offset++] = b ? 0xff : 0x00;
        };

        //WARNING: Changes here mean that you CANNOT write unicode characters that are longer than one byte.
        // This isn't a problem for the current use of this code (ie, not used), but may become an issue in the future.
        Writer.prototype.writeString = function(s, tag) {
            if (typeof(s) !== 'string')
                throw new TypeError('argument must be a string (was: ' + typeof(s) + ')');
            if (typeof(tag) !== 'number')
                tag = ASN1.OctetString;

            var len = s.length;
            this.writeByte(tag);
            this.writeLength(len);
            if (len) {
                this._ensure(len);
                for (var i=0, strLen=s.length; i < strLen; i++) {
                    this._buf[this._offset + i] = s.charCodeAt(i);
                }
                this._offset += len;
            }
        };

        //TODO: Write a Uint8Array instead.
        Writer.prototype.writeBuffer = function(buf, tag) {

            // If no tag is specified we will assume `buf` already contains tag and length
            if (typeof(tag) === 'number') {
                this.writeByte(tag);
                this.writeLength(buf.length);
            }

            this._ensure(buf.length);
            for (var i = 0; i < buf.length; i++) {
                this._buf[i+this._offset] = buf[i];
            }
        //  console.log(this._buf);
            //buf.copy(this._buf, this._offset, 0, buf.length);
            this._offset += buf.length;
        };


        Writer.prototype.writeStringArray = function(strings, tag) {
            if (! (strings instanceof Array))
                throw new TypeError('argument must be an Array[String]');

            var self = this;
            strings.forEach(function(s) {
                self.writeString(s, tag);
            });
        };

        // This is really to solve DER cases, but whatever for now
        Writer.prototype.writeOID = function(s, tag) {
            if (typeof(s) !== 'string')
                throw new TypeError('argument must be a string');
            if (typeof(tag) !== 'number')
                tag = ASN1.OID;

            if (!/^([0-9]+\.){3,}[0-9]+$/.test(s))
                throw new Error('argument is not a valid OID string');

            function encodeOctet(bytes, octet) {
                if (octet < 128) {
                        bytes.push(octet);
                } else if (octet < 16384) {
                        bytes.push((octet >>> 7) | 0x80);
                        bytes.push(octet & 0x7F);
                } else if (octet < 2097152) {
                    bytes.push((octet >>> 14) | 0x80);
                    bytes.push(((octet >>> 7) | 0x80) & 0xFF);
                    bytes.push(octet & 0x7F);
                } else if (octet < 268435456) {
                    bytes.push((octet >>> 21) | 0x80);
                    bytes.push(((octet >>> 14) | 0x80) & 0xFF);
                    bytes.push(((octet >>> 7) | 0x80) & 0xFF);
                    bytes.push(octet & 0x7F);
                } else {
                    bytes.push(((octet >>> 28) | 0x80) & 0xFF);
                    bytes.push(((octet >>> 21) | 0x80) & 0xFF);
                    bytes.push(((octet >>> 14) | 0x80) & 0xFF);
                    bytes.push(((octet >>> 7) | 0x80) & 0xFF);
                    bytes.push(octet & 0x7F);
                }
            }

            var tmp = s.split('.');
            var bytes = [];
            bytes.push(parseInt(tmp[0], 10) * 40 + parseInt(tmp[1], 10));
            tmp.slice(2).forEach(function(b) {
                encodeOctet(bytes, parseInt(b, 10));
            });

            var self = this;
            this._ensure(2 + bytes.length);
            this.writeByte(tag);
            this.writeLength(bytes.length);
            bytes.forEach(function(b) {
                self.writeByte(b);
            });
        };


        Writer.prototype.writeLength = function(len) {
            if (typeof(len) !== 'number')
                throw new TypeError('argument must be a Number');

            this._ensure(4);

            if (len <= 0x7f) {
                this._buf[this._offset++] = len;
            } else if (len <= 0xff) {
                this._buf[this._offset++] = 0x81;
                this._buf[this._offset++] = len;
            } else if (len <= 0xffff) {
                this._buf[this._offset++] = 0x82;
                this._buf[this._offset++] = len >> 8;
                this._buf[this._offset++] = len;
            } else if (len <= 0xffffff) {
                this._buf[this._offset++] = 0x83;
                this._buf[this._offset++] = len >> 16;
                this._buf[this._offset++] = len >> 8;
                this._buf[this._offset++] = len;
            } else {
                throw new InvalidAsn1Error('Length too long (> 4 bytes)');
            }
        };

        Writer.prototype.startSequence = function(tag) {
            if (typeof(tag) !== 'number')
                tag = ASN1.Sequence | ASN1.Constructor;

            this.writeByte(tag);
            this._seq.push(this._offset);
            this._ensure(3);
            this._offset += 3;
        };


        Writer.prototype.endSequence = function() {
            var seq = this._seq.pop();
            var start = seq + 3;
            var len = this._offset - start;

            if (len <= 0x7f) {
                this._shift(start, len, -2);
                this._buf[seq] = len;
            } else if (len <= 0xff) {
                this._shift(start, len, -1);
                this._buf[seq] = 0x81;
                this._buf[seq + 1] = len;
            } else if (len <= 0xffff) {
                this._buf[seq] = 0x82;
                this._buf[seq + 1] = len >> 8;
                this._buf[seq + 2] = len;
            } else if (len <= 0xffffff) {
                this._shift(start, len, 1);
                this._buf[seq] = 0x83;
                this._buf[seq + 1] = len >> 16;
                this._buf[seq + 2] = len >> 8;
                this._buf[seq + 3] = len;
            } else {
                throw new InvalidAsn1Error('Sequence too long');
            }
        };


        Writer.prototype._shift = function(start, len, shift) {

            //this._buf.copy(this._buf, start + shift, start, start + len);
            this._buf.copyWithin(start+shift, start, start+len);
            this._offset += shift;
        };

        Writer.prototype._ensure = function(len) {

            if (this._size - this._offset < len) {
                var sz = this._size * this._options.growthFactor;
                if (sz - this._offset < len)
                    sz += len;

                var buf = new Uint8Array(sz);

                //this._buf.copy(buf, 0, 0, this._offset);

                //TypedArrays have no built-in cross-copy method :(

                for (var i = 0; i < this._offset; i++) {
                    buf[i] = this._buf[i];
                }

                this._buf = buf;
                this._size = sz;
            }
        };

        ///--- API

        function Reader(data) {

            this._buf = data
            this._size = data.length;

            // These hold the "current" state
            this._len = 0;
            this._offset = 0;
        }

        Object.defineProperty(Reader.prototype, 'length', {
            enumerable: true,
            get: function () { return (this._len); }
        });

        Object.defineProperty(Reader.prototype, 'offset', {
            enumerable: true,
            get: function () { return (this._offset); }
        });

        Object.defineProperty(Reader.prototype, 'remain', {
            get: function () { return (this._size - this._offset); }
        });

        Object.defineProperty(Reader.prototype, 'buffer', {
            get: function () { return (this._buf.slice(this._offset)); }
        });


        /**
         * Reads a single byte and advances offset; you can pass in `true` to make this
         * a "peek" operation (i.e., get the byte, but don't advance the offset).
         *
         * @param {Boolean} peek true means don't move offset.
         * @return {Number} the next byte, null if not enough data.
         */
        Reader.prototype.readByte = function(peek) {
            if (this._size - this._offset < 1)
                return null;

            var b = this._buf[this._offset] & 0xff;

            if (!peek)
                this._offset += 1;

            return b;
        };


        Reader.prototype.peek = function() {
            return this.readByte(true);
        };


        /**
         * Reads a (potentially) variable length off the BER buffer.  This call is
         * not really meant to be called directly, as callers have to manipulate
         * the internal buffer afterwards.
         *
         * As a result of this call, you can call `Reader.length`, until the
         * next thing called that does a readLength.
         *
         * @return {Number} the amount of offset to advance the buffer.
         * @throws {InvalidAsn1Error} on bad ASN.1
         */
        Reader.prototype.readLength = function(offset) {
            if (offset === undefined)
                offset = this._offset;

            if (offset >= this._size)
                return null;

            var lenB = this._buf[offset++] & 0xff;
            if (lenB === null)
                return null;

            if ((lenB & 0x80) == 0x80) {
                lenB &= 0x7f;

                if (lenB == 0)
                    throw InvalidAsn1Error('Indefinite length not supported');

                if (lenB > 4)
                    throw InvalidAsn1Error('encoding too long');

                if (this._size - offset < lenB)
                    return null;

                this._len = 0;
                for (var i = 0; i < lenB; i++)
                    this._len = (this._len << 8) + (this._buf[offset++] & 0xff);

            } else {
                // Wasn't a variable length
                this._len = lenB;
            }

            return offset;
        };


        /**
         * Parses the next sequence in this BER buffer.
         *
         * To get the length of the sequence, call `Reader.length`.
         *
         * @return {Number} the sequence's tag.
         */
        Reader.prototype.readSequence = function(tag) {
            var seq = this.peek();
            if (seq === null)
                return null;
            if (tag !== undefined && tag !== seq)
                throw InvalidAsn1Error('Expected 0x' + tag.toString(16) +
                                                                    ': got 0x' + seq.toString(16));

            var o = this.readLength(this._offset + 1); // stored in `length`
            if (o === null)
                return null;

            this._offset = o;
            return seq;
        };


        Reader.prototype.readInt = function(tag) {
            if (typeof(tag) !== 'number')
                tag = ASN1.Integer;

            return this._readTag(ASN1.Integer);
        };


        Reader.prototype.readBoolean = function(tag) {
            if (typeof(tag) !== 'number')
                tag = ASN1.Boolean;

            return (this._readTag(tag) === 0 ? false : true);
        };


        Reader.prototype.readEnumeration = function(tag) {
            if (typeof(tag) !== 'number')
                tag = ASN1.Enumeration;

            return this._readTag(ASN1.Enumeration);
        };


        Reader.prototype.readString = function(tag, retbuf) {
            if (!tag)
                tag = ASN1.OctetString;

            var b = this.peek();
            if (b === null)
                return null;

            if (b !== tag)
                throw InvalidAsn1Error('Expected 0x' + tag.toString(16) +
                                                                    ': got 0x' + b.toString(16));

            var o = this.readLength(this._offset + 1); // stored in `length`

            if (o === null)
                return null;

            if (this.length > this._size - o)
                return null;

            this._offset = o;

            if (this.length === 0)
                return retbuf ? new Uint8Array(0) : '';

            var str = this._buf.slice(this._offset, this._offset + this.length);
            this._offset += this.length;

            var result = '';
            for (var i = 0; i < str.length; i++) {
                result += String.fromCharCode(str[i]);
            }

            return retbuf ? str : result;
        };

        Reader.prototype.readOID = function(tag) {
            if (!tag)
                tag = ASN1.OID;

            var b = this.readString(tag, true);
            if (b === null)
                return null;

            var values = [];
            var value = 0;

            for (var i = 0; i < b.length; i++) {
                var byte = b[i] & 0xff;

                value <<= 7;
                value += byte & 0x7f;
                if ((byte & 0x80) == 0) {
                    values.push(value >>> 0);
                    value = 0;
                }
            }

            value = values.shift();
            values.unshift(value % 40);
            values.unshift((value / 40) >> 0);

            return values.join('.');
        };


        Reader.prototype._readTag = function(tag) {

            var b = this.peek();

            if (b === null)
                return null;

            if (b !== tag)
                throw InvalidAsn1Error('Expected 0x' + tag.toString(16) +
                                                                    ': got 0x' + b.toString(16));

            var o = this.readLength(this._offset + 1); // stored in `length`
            if (o === null)
                return null;

            if (this.length > 4)
                throw InvalidAsn1Error('Integer too long: ' + this.length);

            if (this.length > this._size - o)
                return null;
            this._offset = o;

            var fb = this._buf[this._offset];
            var value = 0;

            for (var i = 0; i < this.length; i++) {
                value <<= 8;
                value |= (this._buf[this._offset++] & 0xff);
            }

            if ((fb & 0x80) == 0x80 && i !== 4)
                value -= (1 << (i * 8));

            return value >> 0;
        };


        ///--- Exported API

        var ber = {
            Writer: Writer,
            Reader: Reader
        };

        return {
            create: function (target, community, options, delegate) {
                return new Session (target, community, options, delegate);
            }
        };
    }
})();
