// © 2016-2018 Fabio Garcia. All rights reserved.

import Hash from './Hash.js';
import Cipher from './Cipher.js';

import Sha256 from './Hash/Sha256.js';
import AES from './Cipher/AES.js';

let Crypto = {};

Crypto.Hash = Hash;
Crypto.Cipher = Cipher;
Crypto.Sha256 = Sha256;
Crypto.AES = AES;

export default Crypto;
