const addon = require('bindings')('systeminformation.node')
const os = require('os');
const { execSync } = require('child_process');
const crypto = require('crypto');

const _platform = process.platform;
const _darwin = (_platform === 'darwin');
let _mac = {};

function getMacAddresses() {
  let iface = '';
  let mac = '';
  let result = {};
  if (_darwin) {
    const cmd = '/sbin/ifconfig';
    let res = execSync(cmd);
    const lines = res.toString().split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (lines[i] && lines[i][0] !== '\t' && lines[i].indexOf(':') > 0) {
        iface = lines[i].split(':')[0];
      } else if (lines[i].indexOf('\tether ') === 0) {
        mac = lines[i].split('\tether ')[1];
        if (iface && mac) {
          result[iface] = mac.trim();
          iface = '';
          mac = '';
        }
      }
    }
  }
  return result;
}

function networkInterfaces() {
  let ifaces = os.networkInterfaces();
  let result = [];
  for (let dev in ifaces) {
    let ip4 = '';
    let ip6 = '';
    let mac = '';
    if (Object.hasOwnProperty.call(ifaces, dev)) {
      ifaces[dev].forEach(function (details) {
        if (details.family === 'IPv4') {
          ip4 = details.address;
        }
        if (details.family === 'IPv6') {
          if (!ip6 || ip6.match(/^fe80::/i)) {
            ip6 = details.address;
          }
        }
        mac = details.mac;
        if (mac.indexOf('00:00:0') > -1 && _darwin) {
          if (Object.keys(_mac).length === 0) {
            _mac = getMacAddresses();
          }
          mac = _mac[dev] || '';
        }
      });
      let internal = (ifaces[dev] && ifaces[dev][0]) ? ifaces[dev][0].internal : null;
      result.push({ iface: dev, ip4: ip4, ip6: ip6, mac: mac, internal: internal });
    }
  }
  return result;
}


const getUUID = () => {
  let UUID = addon.getUUID();
  // 此方法完全是为兼容旧有逻辑
  // 以此方式获取UUID仍有较大的不确定性，以下情况UUID会有变化
  // 例如：断网(Windows、macOS)、网络变化(macOS)
  if(!UUID ||
    UUID.length !== 36 ||
    UUID === '03000200-0400-0500-0006-000700080009' ||
    UUID === '00000000-0000-0000-0000-000000000000' ||
    UUID === 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF') {
    const networkInfo = networkInterfaces();
    const tmp_str = networkInfo
      .filter((item) => Boolean(!item.internal && item.mac))
      .map((item) => item.mac)
      .join('-')
    UUID = crypto.createHash('md5').update(`-${tmp_str}`).digest('hex');
  }
  return UUID || '';
}

module.exports = {
  getUUID: getUUID,
  getSerialNumber: addon.getSerialNumber,
  getSystemArch: addon.getSystemArch,
  getSystemVersion: addon.getSystemVersion,
  getProductName: addon.getProductName,
  getMemorySize: addon.getMemorySize,
  getCPUInfo: addon.getCPUInfo,
  getScreenInfo: addon.getScreenInfo,
  getVendor: addon.getVendor,
  getInfo: () => {
    return {
      uuid: getUUID(),
      serial_number: addon.getSerialNumber(),
      arch: addon.getSystemArch(),
      version: addon.getSystemVersion(),
      product_name: addon.getProductName(),
      memory: addon.getMemorySize(),
      cpu: addon.getCPUInfo(),
      screen_resolution: addon.getScreenInfo(),
      vendor: addon.getVendor()
    }
  }
}