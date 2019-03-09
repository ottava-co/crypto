// © 2016-2018 Fabio Garcia. All rights reserved.

// Dependencies
import Debug from 'ottava-debug';
import Mutable from 'ottava-mutable';

// Class definition
export default class Hash {

  static get size() {
    Debug.abstract(
      'Hash::size',
      '<Integer>'
    );
  }

  static hash(buffer) {
    Debug.abstract(
      'Hash::hash',
      '<Mutable> buffer',
      '<Mutable>'
    );
  }

};
