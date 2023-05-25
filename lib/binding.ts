const addon = require('../build/Release/systeminformation');

export = {
    getDeviceUUID: addon.getDeviceUUID,
    getDeviceSerialNumber: addon.getDeviceSerialNumber,
    getDeviceSystemArch: addon.getDeviceSystemArch,
    getDeviceSystemVersion: addon.getDeviceSystemVersion,
    getDeviceProductName: addon.getDeviceProductName,
    getDeviceMemorySize: addon.getDeviceMemorySize,
    getDeviceCPUInfo: addon.getDeviceCPUInfo,
    getDeviceScreenInfo: addon.getDeviceScreenInfo,
    getDeviceManufacturer: addon.getDeviceManufacturer,
    getDeviceInfo: () => {
        return {
            uuid: addon.getDeviceUUID(),
            serial_number: addon.getDeviceSerialNumber(),
            arch: addon.getDeviceSystemArch(),
            version: addon.getDeviceSystemVersion(),
            product_name: addon.getDeviceProductName(),
            memory: addon.getDeviceMemorySize(),
            cpu: addon.getDeviceCPUInfo(),
            screen_resolution: addon.getDeviceScreenInfo(),
            vendor: addon.getDeviceManufacturer(),
        }
    },
}
