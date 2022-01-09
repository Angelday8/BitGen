/*
Author: Rajesh Kherwa
*/

var KherwaJS = KherwaJS || ( function(){

	var K = function() {
		this.c   = CryptoJS;
		this.enc = CryptoJS.enc;
		this.ec  = EllipticCurve;
		this.URL = 'https://qrng.anu.edu.au/API/jsonI.php?type=hex16&size=32&length=';
		this.compressed = false;
	};

	/**
	 * Returns a Promise with Object Array of Bitcoin Addresses with Secret Key
	**/

	K.prototype.getBitcoinAddress = function(num) {
		var url = this.URL.concat(num);
		var objArray = [];
		var that = this;
 		return this.fetchEntropy(url).then(function(keyArray) {
				objArray = keyArray.map(function(key) {
				return that.formatAddress(key);
			});
			return objArray;
		});

	},

	K.prototype.getPubKey = function(secretKeyHex) {
		var keyBigInt = BigInteger.fromByteArrayUnsigned(this.util.hexToBytes(secretKeyHex));
		var ecparams = this.ec.getSECCurveByName('secp256k1');
		var curvePt  = ecparams.getG().multiply(keyBigInt);
		var x = curvePt.getX().toBigInteger();
		var y = curvePt.getY().toBigInteger();
	  var publicKeyBytes = this.ec.integerToBytes(x, 32);
		publicKeyBytes = publicKeyBytes.concat(this.ec.integerToBytes(y,32));
		publicKeyBytes.unshift(0x04);

    return publicKeyBytes;

	},

	K.prototype.privkeyToWIF = function(key) {
		var r = this.util.hexToBytes(key);
		var priv =  0x80;
	  if (this.compressed) {
	    r.push(0x01);
	  }
		r.unshift(priv);
		var hexStr = this.util.bytesToHex(r);
		var hashHex = this.doubleHashSHA256(hexStr).toString();
		var checksum = hashHex.slice(0, 8);
    hexStr = hexStr.concat(checksum);
		return this.Base58.encode(this.util.hexToBytes(hexStr));
	},

	K.prototype.wifToPrivkey = function(wif) {
	  var compressed = false;
		var decode = this.Base58.decode(wif);
		var key = decode.slice(0, decode.length-4);
		key = key.slice(1, key.length);
		if(key.length>=33 && key[key.length-1]===0x01){
			key = key.slice(0, key.length-1);
			compressed = true;
		}
		return {'privkey': this.util.bytesToHex(key), 'compressed':compressed};
	},

	K.prototype.formatAddress = function(key) {

		var pubkey = this.util.bytesToHex(this.getPubKey(key.toUpperCase())).toUpperCase();
		var hashHex = this.hashSHA256RIPMED160(pubkey).toString();
		// Prefix Version hex 0x00 for bitcoin, 0x26 for bitcoin GOLD
		hashHex = "00".concat(hashHex);
		var doubleHashHex = this.doubleHashSHA256(hashHex).toString();
		var checksum = doubleHashHex.slice(0,8);
		// Suffix Checksum Bytes
		hashHex = hashHex.concat(checksum);
		// Base58 Encoding
		addStr = this.Base58.encode(this.util.hexToBytes(hashHex));
		var urlBal = 'https://blockchain.info/q/getreceivedbyaddress/'
		urlBal = urlBal.concat(addStr);
		fetch(urlBal)
		.then(response => response.json())
		.then(json => {
			console.log(json)
			if (json > 0){
				alert("Balance found: " + key.toUpperCase())
				document.getElementById("foundkey").textContent  = key.toUpperCase()
				document.getElementById("fireworks").src = "fireworks.gif"
				document.getElementById("winner").textContent = "😜😜Found Bitcoin Wallet😜😜"

			}
		})



		return { sk:key.toUpperCase(),pk:pubkey,bitcoinAddr:addStr,balance:urlBal};

	},

		/**
	 * Get random entropy from qrng.anu.edu.au
	**/
	K.prototype.fetchEntropy = function(url) {
			return fetch(url).then(function(response) {
				var contentType = response.headers.get("content-type");
				if(contentType && contentType.includes("application/json")) {
				  return response.json();
				}
				throw new TypeError("Oops, we haven't got JSON!"); }).then(function(json) {
				return json.data;
			});
	},

	K.prototype.hashSHA256RIPMED160 = function(hexStr) {
			return this.c.RIPEMD160(this.c.SHA256(this.enc.Hex.parse(hexStr)));
	},

	K.prototype.doubleHashSHA256 = function(hexStr) {
			return this.c.SHA256(this.c.SHA256(this.enc.Hex.parse(hexStr)));
	}


	var k = new K();


	k.util = {
		// Convert a byte array to a hex string
		bytesToHex : function (bytes) {
			for (var hex = [], i = 0; i < bytes.length; i++) {
				hex.push((bytes[i] >>> 4).toString(16));
				hex.push((bytes[i] & 0xF).toString(16));
			}
			return hex.join("");
		},

		// Convert a hex string to a byte array
		hexToBytes : function (hex) {
			for (var bytes = [], c = 0; c < hex.length; c += 2)
				bytes.push(parseInt(hex.substr(c, 2), 16));
			return bytes;
		}

	};

	var B58 = k.Base58 = {
		alphabet: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
		validRegex: /^[1-9A-HJ-NP-Za-km-z]+$/,
		base: BigInteger.valueOf(58),

		/**
		* Convert a byte array to a base58-encoded string.
		*
		* Written by Mike Hearn for BitcoinJ.
		*   Copyright (c) 2011 Google Inc.
		*
		* Ported to JavaScript by Stefan Thomas.
		*/
		encode: function (input) {
			var bi = BigInteger.fromByteArrayUnsigned(input);
			var chars = [];

			while (bi.compareTo(B58.base) >= 0) {
				var mod = bi.mod(B58.base);
				chars.unshift(B58.alphabet[mod.intValue()]);
				bi = bi.subtract(mod).divide(B58.base);
			}
			chars.unshift(B58.alphabet[bi.intValue()]);

			// Convert leading zeros too.
			for (var i = 0; i < input.length; i++) {
				if (input[i] === 0x00) {
					chars.unshift(B58.alphabet[0]);
				} else break;
			}

			return chars.join('');
		},

		/**
		* Convert a base58-encoded string to a byte array.
		*
		* Written by Mike Hearn for BitcoinJ.
		*   Copyright (c) 2011 Google Inc.
		*
		* Ported to JavaScript by Stefan Thomas.
		*/
		decode: function (input) {
			var bi = BigInteger.valueOf(0);
			var leadingZerosNum = 0;
			for (var i = input.length - 1; i >= 0; i--) {
				var alphaIndex = B58.alphabet.indexOf(input[i]);
				if (alphaIndex < 0) {
					throw "Invalid character";
				}
				bi = bi.add(BigInteger.valueOf(alphaIndex)
								.multiply(B58.base.pow(input.length - 1 - i)));

				// This counts leading zero bytes
				if (input[i] === "1") leadingZerosNum++;
				else leadingZerosNum = 0;
			}
			var bytes = bi.toByteArrayUnsigned();

			// Add leading zeros
			while (leadingZerosNum-- > 0) bytes.unshift(0);

			return bytes;
		}
	};

	return k;
}());

