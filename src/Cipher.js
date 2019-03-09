// © 2016-2018 Fabio Garcia. All rights reserved.

import Debug from 'ottava-debug';

export default class Cipher {

  static encrypt(key, iv, buffer) {
    Debug.abstract(
      'Cipher::encrypt',
      '<ArrayBuffer> key',
      '<ArrayBuffer> iv',
      '<ArrayBuffer> buffer',
      '<ArrayBuffer>'
    );
  }

  static decrypt(key, iv, buffer) {
    Debug.abstract(
      'Cipher::decrypt',
      '<ArrayBuffer> key',
      '<ArrayBuffer> iv',
      '<ArrayBuffer> buffer',
      '<ArrayBuffer>'
    );
  }

};
