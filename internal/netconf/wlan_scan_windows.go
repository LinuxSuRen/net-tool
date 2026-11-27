//go:build windows

package netconf

import (
	"syscall"
	"unsafe"
)

var (
	wlanAPIDLL      = syscall.NewLazyDLL("wlanapi.dll")
	wlanOpenHandle  = wlanAPIDLL.NewProc("WlanOpenHandle")
	wlanEnumIfaces  = wlanAPIDLL.NewProc("WlanEnumInterfaces")
	wlanScan        = wlanAPIDLL.NewProc("WlanScan")
	wlanCloseHandle = wlanAPIDLL.NewProc("WlanCloseHandle")
	wlanFreeMemory  = wlanAPIDLL.NewProc("WlanFreeMemory")
)

// Mirrors WLAN_INTERFACE_INFO from wlanapi.h. The description is 256 WCHARs.
type wlanInterfaceInfo struct {
	GUID        syscall.GUID
	Description [256]uint16
	State       uint32
}

type wlanInterfaceInfoList struct {
	Count uint32
	Index uint32
	First wlanInterfaceInfo
}

// triggerWlanScan asks the native WLAN service to refresh its visible-network
// cache. After a successful join, `netsh wlan show networks` can report only
// the connected SSID until a fresh scan runs; without this, the UI looks as
// though every other network vanished.
func triggerWlanScan() error {
	var negotiated uint32
	var handle syscall.Handle
	ret, _, callErr := wlanOpenHandle.Call(2, 0,
		uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&handle)))
	if ret != 0 {
		if callErr != nil {
			return callErr
		}
		return syscall.Errno(ret)
	}
	defer wlanCloseHandle.Call(uintptr(handle), 0)

	var list *wlanInterfaceInfoList
	ret, _, callErr = wlanEnumIfaces.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&list)))
	if ret != 0 {
		if callErr != nil {
			return callErr
		}
		return syscall.Errno(ret)
	}
	if list == nil {
		return nil
	}
	defer wlanFreeMemory.Call(uintptr(unsafe.Pointer(list)))

	base := unsafe.Pointer(&list.First)
	size := int(unsafe.Sizeof(wlanInterfaceInfo{}))
	for i := uint32(0); i < list.Count; i++ {
		info := (*wlanInterfaceInfo)(unsafe.Add(base, int(i)*size))
		ret, _, callErr = wlanScan.Call(uintptr(handle),
			uintptr(unsafe.Pointer(&info.GUID)), 0, 0, 0)
		if ret != 0 {
			if callErr != nil {
				return callErr
			}
			return syscall.Errno(ret)
		}
	}
	return nil
}
