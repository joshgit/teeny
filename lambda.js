console.log('Loading function');

var aws = require('aws-sdk');
var ddb = new aws.DynamoDB();

function add_link_to_table(hash, num_chars, link, success, fail) {
    if (num_chars > hash.length) {
        console.log('Warning, whole hash already in the table: ' + hash);
        success(hash);
        return;
    }

    var hash_prefix = hash.substring(0, num_chars);
    var params = {
        "TableName": "hashToLink",
        "Item": {
            "hash": {"S": hash_prefix},
            "link": {"S": link}
        },
        "ConditionExpression": "#hash <> :hash",
        "ExpressionAttributeNames": {"#hash": "hash"},
        "ExpressionAttributeValues": {
            ":hash": {"S": hash_prefix}
        }
    };
    ddb.putItem(params, function(err, data) {
        if (err) {
            if (err.code === 'ConditionalCheckFailedException') {
                console.log(hash_prefix + ' already in table as hash, trying to insert with one more character.');
                add_link_to_table(hash, num_chars + 1, link, success, fail);
            } else {
                fail(err);
            }
        }
        else {
            success(hash_prefix);
        }
    });
}

function get_link_from_table_by_hash(hash, success, fail) {

    var params = {
        "TableName": "hashToLink",
        "Key": {
            'hash': { "S": hash }
        },
        "AttributesToGet": [
            "link"
        ],
        "ConsistentRead": true
    };
    ddb.getItem(params, function(err, data) {
        if (err) {
            fail(err);
        }
        else {
            success(data);
        }
    });
}

function get_hash_by_link(link, success, fail) {

    var params = {
        "TableName": "hashToLink",
        "IndexName": "link-index",
        "KeyConditionExpression": "link = :link",
        "ExpressionAttributeValues": {
            ":link": {"S": link}
        }
    };

    ddb.query(params, function(err, data) {
        if (err) {
            fail(err);
        }
        else {
            success(data);
        }
    });
}

exports.handler = function(event, context) {
    console.log('Received event:', JSON.stringify(event, null, 2));

    if (event.encode) {
        // store hash and link in hashToLink DDB table.
        // check from 4 to 10 digits for already being in the table
        // use first substring that's not already in the table
        var hash = Sha1.hash(event.encode);

        get_hash_by_link(event.encode, 
            function(data) {
                console.log("get_hash_by_link !!!!: " + JSON.stringify(data, null, 2));
                if (data && data.Count > 0 && data.Items[0].hash) {
                    console.log('succeeding with existing hash: ' + data.Items[0].hash.S);
                    context.succeed({ e: data.Items[0].hash.S });
                } else {
                    // start by attempting to add first 5 chars of hash to ddb table
                    add_link_to_table(hash, 5, event.encode, function(hash_prefix_added) {
                        console.log('succeeding with new hash: ' + hash_prefix_added);
                        context.succeed({
                            e: hash_prefix_added
                        });
                        return;
                    });
                }
                return;
            }, 
            function(err) {
                console.log(err);
            });
        return;
    }
    else if (event.decode) {
        // check if 'event.decode' is a hash in hashToLink DDB table
        // if not, we have no link for this hash
        // if it is, return that
        get_link_from_table_by_hash(event.decode, function(data) {
            var result = {};
            if (data && data.Item && data.Item.link && data.Item.link.S) {
                result.d = data.Item.link.S;
            }
            context.succeed(result);
        }, function(data) {
            console.log(data);
            context.succeed({
                d: 'decoded ' + data
            });
        });
        return;
    }

    context.succeed({
        e: event.encode,
        d: event.decode
    });
};

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/*  SHA-1 implementation in JavaScript                  (c) Chris Veness 2002-2014 / MIT Licence  */
/*                                                                                                */
/*  - see http://csrc.nist.gov/groups/ST/toolkit/secure_hashing.html                              */
/*        http://csrc.nist.gov/groups/ST/toolkit/examples.html                                    */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

/* jshint node:true *//* global define, escape, unescape */
'use strict';


/**
 * SHA-1 hash function reference implementation.
 *
 * @namespace
 */
var Sha1 = {};


/**
 * Generates SHA-1 hash of string.
 *
 * @param   {string} msg - (Unicode) string to be hashed.
 * @returns {string} Hash of msg as hex character string.
 */
Sha1.hash = function(msg) {
    // convert string to UTF-8, as SHA only deals with byte-streams
    msg = msg.utf8Encode();

    // constants [§4.2.1]
    var K = [ 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 ];

    // PREPROCESSING

    msg += String.fromCharCode(0x80);  // add trailing '1' bit (+ 0's padding) to string [§5.1.1]

    // convert string msg into 512-bit/16-integer blocks arrays of ints [§5.2.1]
    var l = msg.length/4 + 2; // length (in 32-bit integers) of msg + ‘1’ + appended length
    var N = Math.ceil(l/16);  // number of 16-integer-blocks required to hold 'l' ints
    var M = new Array(N);

    for (var i=0; i<N; i++) {
        M[i] = new Array(16);
        for (var j=0; j<16; j++) {  // encode 4 chars per integer, big-endian encoding
            M[i][j] = (msg.charCodeAt(i*64+j*4)<<24) | (msg.charCodeAt(i*64+j*4+1)<<16) |
                (msg.charCodeAt(i*64+j*4+2)<<8) | (msg.charCodeAt(i*64+j*4+3));
        } // note running off the end of msg is ok 'cos bitwise ops on NaN return 0
    }
    // add length (in bits) into final pair of 32-bit integers (big-endian) [§5.1.1]
    // note: most significant word would be (len-1)*8 >>> 32, but since JS converts
    // bitwise-op args to 32 bits, we need to simulate this by arithmetic operators
    M[N-1][14] = ((msg.length-1)*8) / Math.pow(2, 32); M[N-1][14] = Math.floor(M[N-1][14]);
    M[N-1][15] = ((msg.length-1)*8) & 0xffffffff;

    // set initial hash value [§5.3.1]
    var H0 = 0x67452301;
    var H1 = 0xefcdab89;
    var H2 = 0x98badcfe;
    var H3 = 0x10325476;
    var H4 = 0xc3d2e1f0;

    // HASH COMPUTATION [§6.1.2]

    var W = new Array(80); var a, b, c, d, e;
    for (var i=0; i<N; i++) {

        // 1 - prepare message schedule 'W'
        for (var t=0;  t<16; t++) W[t] = M[i][t];
        for (var t=16; t<80; t++) W[t] = Sha1.ROTL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);

        // 2 - initialise five working variables a, b, c, d, e with previous hash value
        a = H0; b = H1; c = H2; d = H3; e = H4;

        // 3 - main loop
        for (var t=0; t<80; t++) {
            var s = Math.floor(t/20); // seq for blocks of 'f' functions and 'K' constants
            var T = (Sha1.ROTL(a,5) + Sha1.f(s,b,c,d) + e + K[s] + W[t]) & 0xffffffff;
            e = d;
            d = c;
            c = Sha1.ROTL(b, 30);
            b = a;
            a = T;
        }

        // 4 - compute the new intermediate hash value (note 'addition modulo 2^32')
        H0 = (H0+a) & 0xffffffff;
        H1 = (H1+b) & 0xffffffff;
        H2 = (H2+c) & 0xffffffff;
        H3 = (H3+d) & 0xffffffff;
        H4 = (H4+e) & 0xffffffff;
    }

    return Sha1.toHexStr(H0) + Sha1.toHexStr(H1) + Sha1.toHexStr(H2) +
           Sha1.toHexStr(H3) + Sha1.toHexStr(H4);
};


/**
 * Function 'f' [§4.1.1].
 * @private
 */
Sha1.f = function(s, x, y, z)  {
    switch (s) {
        case 0: return (x & y) ^ (~x & z);           // Ch()
        case 1: return  x ^ y  ^  z;                 // Parity()
        case 2: return (x & y) ^ (x & z) ^ (y & z);  // Maj()
        case 3: return  x ^ y  ^  z;                 // Parity()
    }
};

/**
 * Rotates left (circular left shift) value x by n positions [§3.2.5].
 * @private
 */
Sha1.ROTL = function(x, n) {
    return (x<<n) | (x>>>(32-n));
};


/**
 * Hexadecimal representation of a number.
 * @private
 */
Sha1.toHexStr = function(n) {
    // note can't use toString(16) as it is implementation-dependant,
    // and in IE returns signed numbers when used on full words
    var s="", v;
    for (var i=7; i>=0; i--) { v = (n>>>(i*4)) & 0xf; s += v.toString(16); }
    return s;
};


/** Extend String object with method to encode multi-byte string to utf8
 *  - monsur.hossa.in/2012/07/20/utf-8-in-javascript.html */
if (typeof String.prototype.utf8Encode == 'undefined') {
    String.prototype.utf8Encode = function() {
        return unescape( encodeURIComponent( this ) );
    };
}

/** Extend String object with method to decode utf8 string to multi-byte */
if (typeof String.prototype.utf8Decode == 'undefined') {
    String.prototype.utf8Decode = function() {
        try {
            return decodeURIComponent( escape( this ) );
        } catch (e) {
            return this; // invalid UTF-8? return as-is
        }
    };
}