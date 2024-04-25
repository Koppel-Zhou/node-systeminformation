import bindings from 'bindings';
import os from 'os';
import { execSync } from 'child_process';
import crypto from 'crypto';
const addon = bindings('systeminformation.node');

const _platform = process.platform;
const _darwin = (_platform === 'darwin');
let _mac: any = {};

function getMacAddresses() {
  let iface = '';
  let mac = '';
  let result: any = {};
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
  let ifaces: any = os.networkInterfaces();
  let result: any = [];
  for (let dev in ifaces) {
    let ip4 = '';
    let ip6 = '';
    let mac = '';
    if (Object.hasOwnProperty.call(ifaces, dev)) {
      ifaces[dev].forEach(function (details: any) {
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
    UUID === 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF' ||
    UUID === 'FEFEFEFE-FEFE-FEFE-FEFE-FEFEFEFEFEFE' ||
    UUID === '12345678-1234-5678-90AB-CDDEEFAABBCC') {
    const networkInfo = networkInterfaces();
    const tmp_str = networkInfo
      .filter((item: any) => Boolean(!item.internal && item.mac))
      .map((item: any) => item.mac)
      .join('-')
    UUID = crypto.createHash('md5').update(`-${tmp_str}`).digest('hex');
  }
  return UUID || '';
}

export default {
  getUUID: getUUID,
  getSerialNumber: addon.getSerialNumber,
  getSystemArch: addon.getSystemArch,
  getSystemVersion: addon.getSystemVersion,
  getProductName: addon.getProductName,
  getMemorySize: addon.getMemorySize,
  getCPU: addon.getCPU,
  getScreenInfo: addon.getScreenInfo,
  getVendor: addon.getVendor,
  getCaption: addon.getCaption,
  getAudioDevices: addon.getAudioDevices,
  getVideoDevices: addon.getVideoDevices,
  getMicrophoneDevices: addon.getMicrophoneDevices,
  getSpeakerDevices: addon.getSpeakerDevices,
  getGraphic: addon.getGraphic,
  getDiskSpaceInfo: addon.getDiskSpaceInfo,
  regEditAdd: addon.regEditAdd,
  regEditDelete: addon.regEditDelete,
  getInfo: () => {
    return {
      uuid: getUUID(),
      serial_number: addon.getSerialNumber(),
      arch: addon.getSystemArch(),
      version: addon.getSystemVersion(),
      product_name: addon.getProductName(),
      memory: addon.getMemorySize(),
      cpu: addon.getCPU(),
      screen_resolution: addon.getScreenInfo(),
      vendor: addon.getVendor()
    }
  }
}