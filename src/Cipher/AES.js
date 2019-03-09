// © 2016-2018 Fabio Garcia. All rights reserved.

// Dependencies
import Debug from 'ottava-debug';
import Mutable from 'ottava-mutable';

// Base abstraction
import Cipher from '../Cipher.js';

// AES protected methods:
let _AES = {};

function Init() {
  _AES.Sbox = new Array(99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,
    118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,
    147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,
    7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,
    47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,
    251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,
    188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,
    100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,
    50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,
    78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,
    116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,
    158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,
    137,13,191,230,66,104,65,153,45,15,176,84,187,22);
  _AES.ShiftRowTab = new Array(0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11);
  _AES.Sbox_Inv = new Array(256);
  for(var i = 0; i < 256; i++) {
    _AES.Sbox_Inv[_AES.Sbox[i]] = i;
  }
  _AES.ShiftRowTab_Inv = new Array(16);
  for(var i = 0; i < 16; i++) {
    _AES.ShiftRowTab_Inv[_AES.ShiftRowTab[i]] = i;
  }
  _AES.xtime = new Array(256);
  for(var i = 0; i < 128; i++) {
    _AES.xtime[i] = i << 1;
    _AES.xtime[128 + i] = (i << 1) ^ 0x1b;
  }
}

function SubBytes(state, sbox) {
  for(var i = 0; i < 16; i++) {
    state[i] = sbox[state[i]];  
  }
}

function AddRoundKey(state, rkey) {
  for(var i = 0; i < 16; i++) {
    state[i] ^= rkey[i];
  }
}

function ShiftRows(state, shifttab) {
  var h = new Array().concat(state);
  for(var i = 0; i < 16; i++) {
    state[i] = h[shifttab[i]];
  }
}

function MixColumns(state) {
  for(var i = 0; i < 16; i += 4) {
    var s0 = state[i + 0], s1 = state[i + 1];
    var s2 = state[i + 2], s3 = state[i + 3];
    var h = s0 ^ s1 ^ s2 ^ s3;
    state[i + 0] ^= h ^ _AES.xtime[s0 ^ s1];
    state[i + 1] ^= h ^ _AES.xtime[s1 ^ s2];
    state[i + 2] ^= h ^ _AES.xtime[s2 ^ s3];
    state[i + 3] ^= h ^ _AES.xtime[s3 ^ s0];
  }
}

function MixColumns_Inv(state) {
  for(var i = 0; i < 16; i += 4) {
    var s0 = state[i + 0], s1 = state[i + 1];
    var s2 = state[i + 2], s3 = state[i + 3];
    var h = s0 ^ s1 ^ s2 ^ s3;
    var xh = _AES.xtime[h];
    var h1 = _AES.xtime[_AES.xtime[xh ^ s0 ^ s2]] ^ h;
    var h2 = _AES.xtime[_AES.xtime[xh ^ s1 ^ s3]] ^ h;
    state[i + 0] ^= h1 ^ _AES.xtime[s0 ^ s1];
    state[i + 1] ^= h2 ^ _AES.xtime[s1 ^ s2];
    state[i + 2] ^= h1 ^ _AES.xtime[s2 ^ s3];
    state[i + 3] ^= h2 ^ _AES.xtime[s3 ^ s0];
  }
}

function ExpandKey(key) {
  var kl = key.length, ks, Rcon = 1;
  switch (kl) {
    case 16: ks = 16 * (10 + 1); break;
    case 24: ks = 16 * (12 + 1); break;
    case 32: ks = 16 * (14 + 1); break;
    default: 
      Debug.throw(
        'AES::ExpandKey',
        'Only key lengths of 16, 24, or 32 bytes allowed!',
        key
      );
  }
  for(var i = kl; i < ks; i += 4) {
    var temp = key.slice(i - 4, i);
    if (i % kl == 0) {
      temp = new Array(_AES.Sbox[temp[1]] ^ Rcon, _AES.Sbox[temp[2]], 
      _AES.Sbox[temp[3]], _AES.Sbox[temp[0]]); 
      if ((Rcon <<= 1) >= 256) {
        Rcon ^= 0x11b;
      }
    } else if ((kl > 24) && (i % kl == 16)) {
      temp = new Array(
        _AES.Sbox[temp[0]],
        _AES.Sbox[temp[1]], 
        _AES.Sbox[temp[2]], 
        _AES.Sbox[temp[3]]
      );
    }
    for(var j = 0; j < 4; j++) {
      key[i + j] = key[i + j - kl] ^ temp[j];
    }
  }
}

function Encrypt(block, key) {
  var l = key.length;
  AddRoundKey(block, key.slice(0, 16));
  for(var i = 16; i < l - 16; i += 16) {
    SubBytes(block, _AES.Sbox);
    ShiftRows(block, _AES.ShiftRowTab);
    MixColumns(block);
    AddRoundKey(block, key.slice(i, i + 16));
  }
  SubBytes(block, _AES.Sbox);
  ShiftRows(block, _AES.ShiftRowTab);
  AddRoundKey(block, key.slice(i, l));
}

function Decrypt(block, key) {
  var l = key.length;
  AddRoundKey(block, key.slice(l - 16, l));
  ShiftRows(block, _AES.ShiftRowTab_Inv);
  SubBytes(block, _AES.Sbox_Inv);
  for(var i = l - 32; i >= 16; i -= 16) {
    AddRoundKey(block, key.slice(i, i + 16));
    MixColumns_Inv(block);
    ShiftRows(block, _AES.ShiftRowTab_Inv);
    SubBytes(block, _AES.Sbox_Inv);
  }
  AddRoundKey(block, key.slice(0, 16));
}

function Done() {
  delete _AES.Sbox_Inv;
  delete _AES.ShiftRowTab_Inv;
  delete _AES.xtime;
}


export default class AES extends Cipher {

  // AES CBC Encrypt
  static encrypt(key, iv, buffer) {
    Debug.valid(key, iv, buf, Mutable);
    let keyex = key.slice(0),
        blkba = blk.rightPad(0x00, blk.length % 16);
    Init();
    ExpandKey(keyex);
    let enc = new Mutable(iv); //Bytes.Generate(this.random, 16);
    for(let i = 0; i < blkba.length/16; i++) {
      let tmpba = blkba.slice((i*16), (i*16)+16),
          preba = enc.slice((i*16), (i*16)+16);
      tmpba = preba.xor(tmpba);
      Encrypt(tmpba, keyex);
      enc = enc.concat(tmpba);
    }
    Done();
    return enc;
  }

  // AES CBC Decrypt
  static decrypt(key, iv , buffer) {
    Debug.valid(key, iv , buffer, Mutable);
    let keyex = key.slice(0),

        dec = new Mutable();
    Init();
    ExpandKey(keyex);
    for(let i = 1; i < (buf.length/16); i++) {
      let tmpba = buf.slice((i*16), (i*16)+16),
          preba = buf.slice(((i-1)*16), ((i-1)*16)+16);
      Decrypt(tmpba, keyex);
      tmpba = preba.xor(tmpba);
      dec = dec.concat(tmpba);
    }
    Done();
    return dec.rightDepad(0x00);
  }

};
