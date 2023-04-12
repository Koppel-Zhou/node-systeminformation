const si = require("../dist/binding.js");
const assert = require("assert");
const { performance } = require("perf_hooks");
assert(si.getDeviceUUID, "The expected functionundefined");
const { exec } = require('child_process');

function testBasic()
{   
    const start = performance.now();
    const result = si.getDeviceUUID();
    console.log(`DeviceUUID`.padEnd(20), `${result}`.padEnd(40), `耗时 ${performance.now() - start}`);
    const start2 = performance.now();
    const result2 = si.getDeviceSerialNumber();
    console.log(`DeviceSerialNumber`.padEnd(20), `${result2}`.padEnd(40), `耗时 ${performance.now() - start2}`);
    const start3 = performance.now();
    const result3 = si.getDeviceSystemArch();
    console.log(`DeviceSystemArch`.padEnd(20), `${result3}`.padEnd(40), `耗时 ${performance.now() - start3}`);
    const start4 = performance.now();
    const result4 = si.getDeviceSystemVersion();
    console.log(`DeviceSystemVersion`.padEnd(20), `${result4}`.padEnd(40), `耗时 ${performance.now() - start4}`);
    const start5 = performance.now();
    const result5 = si.getDeviceProductName();
    console.log(`DeviceProductName`.padEnd(20), `${result5}`.padEnd(40), `耗时 ${performance.now() - start5}`);
    const start6 = performance.now();
    const result6 = si.getDeviceMemorySize();
    console.log(`DeviceMemorySize`.padEnd(20), `${result6}`.padEnd(40), `耗时 ${performance.now() - start6}`);
    const start7 = performance.now();
    const result7 = si.getDeviceCPUInfo();
    console.log(`DeviceCPUInfo`.padEnd(20), `${result7}`.padEnd(40), `耗时 ${performance.now() - start7}`);
    const start8 = performance.now();
    const result8 = si.getDeviceScreenInfo();
    console.log(`DeviceScreenInfo`.padEnd(20), `${JSON.stringify(result8)}`.padEnd(40), `耗时 ${performance.now() - start8}`);
    const start9 = performance.now();
    const result9 = si.getDeviceManufacturer();
    console.log(`DeviceManufacturer`.padEnd(20), `${result9}`.padEnd(40), `耗时 ${performance.now() - start9}`);
    const start10 = performance.now();
    const result10 = si.getDeviceInfo();
    console.log(`DeviceInfo`.padEnd(20), `\n${JSON.stringify(result10)}`.padEnd(40), `\n耗时 ${performance.now() - start10}`);
}

assert.doesNotThrow(testBasic, undefined, "testBasic threw an expection");

console.log("Tests passed- everything looks OK!");