// © 2016-2018 Fabio Garcia. All rights reserved.

import Debug from 'ottava-debug';

export default class Hash {

  static get size() {
    Debug.abstract(
      'Hash::size',
      '<integer>'
    );
  }

  static hash(buffer) {
    Debug.abstract(
      'Hash::hash',
      '<ArrayBuffer> buffer',
      '<string>'
    );
  }

};
