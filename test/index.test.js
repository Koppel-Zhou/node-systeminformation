const si = require('../dist/index').default;
const assert = require('assert');
const perf_hooks = require('perf_hooks');
function testBasic() {
  for (let key in si) {
    const start = perf_hooks.performance.now();
    console.log('>>>', key)
    let result = null;
    if (key === 'getDiskSpaceInfo') {
      result = si[key]('/');
    } else if (key === 'regEditAdd') {
      // result = si[key]("HKEY_CURRENT_USER", "SOFTWARE\\5ETest\\hhh\\MyValueName","test", "REG_SZ", "hahaha");
    } else if (key === 'regEditDelete') {
      result = si[key]("HKEY_CURRENT_USER", "SOFTWARE\\5ETest\\hhh\\MyValueName\\test");
    } else {
      result = si[key]('/');
    }
    
    console.log(
      `----------------------------------------\nCall ${key}`.padEnd(20),
      `\n\nResult:\n${JSON.stringify(result)}`.padEnd(40),
      `\n\nCost time ${perf_hooks.performance.now() - start}ms`
    );
  }

  return 0;
}

assert.doesNotThrow(testBasic, () => console.log('Tests passed- everything looks OK!'), 'testBasic threw an expection')

