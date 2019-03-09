// © 2016-2018 Fabio Garcia. All rights reserved.

// Dependencies
import Debug from 'ottava-debug';
import Mutable from 'ottava-mutable';

// Class definition
export default class Cipher {

  static encrypt(key, iv, buffer) {
    Debug.abstract(
      'Cipher::encrypt',
      '<Mutable> key',
      '<Mutable> iv',
      '<Mutable> buffer',
      '<Mutable>'
    );
  }

  static decrypt(key, iv, buffer) {
    Debug.abstract(
      'Cipher::decrypt',
      '<Mutable> key',
      '<Mutable> iv',
      '<Mutable> buffer',
      '<Mutable>'
    );
  }

};
