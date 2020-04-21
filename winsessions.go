package service

import (
	"fmt"
	"github.com/kardianos/osext"
	"github.com/winlabs/gowin32/wrappers"
	"golang.org/x/sys/windows"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zwinsessions.go winsessions.go
//sys GetUserNameEx(nameFormat uint32, nameBuffre *uint16, nSize *uint32) (err error) [failretval&0xff==0] = secur32.GetUserNameExW
//sys TranslateName(accName *uint16, accNameFormat uint32, desiredNameFormat uint32, translatedName *uint16, nSize *uint32) (err error) [failretval&0xff==0] = secur32.TranslateNameW
//sys WTSQueryUserToken(sessionId uint32, phToken *windows.Handle) (err error) [failretval&0xff==0] = wtsapi32.WTSQueryUserToken
//sys GetTokenInformation(tokenHandle windows.Handle, tokenInformationClass TOKEN_INFORMATION_CLASS, tokenInformation *byte, tokenInformationLength uint32, returnLength *uint32) (err error) [failretval&0xff==0] = advapi32.GetTokenInformation
//sys WTSGetActiveConsoleSessionId() (sessionId uint32, err error) [failretval==0xFFFFFFFF] = kernel32.WTSGetActiveConsoleSessionId
//sys GetUserProfileDirectory(hToken windows.Handle, lpProfileDir *uint16, lpcchSize *uint32) [failretval&0xff==0] (err error) = userenv.GetUserProfileDirectoryW
//sys WTSQuerySessionInformation(hServer windows.Handle, sessionId uint32, WTSInfoClass WTS_INFO_CLASS, buffer *uintptr, bytesReturned *uint32) (err error) [failretval==0] = wtsapi32.WTSQuerySessionInformationW

type WTSSESSION_NOTIFICATION struct {
	Size      uint32
	SessionId uint32
}

const (
	CREATE_BREAKAWAY_FROM_JOB = 0x01000000
	CREATE_NEW_CONSOLE        = 0x00000010
	CREATE_NEW_PROCESS_GROUP  = 0x00000200

	MAX_PATH = 260
)

type TOKEN_INFORMATION_CLASS uint32

func SidToUsername(sid *windows.SID) (string, error) {
	username, domainName, _, err := sid.LookupAccount("")
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/%s", domainName, username), nil
}

// https://gist.github.com/petemoore/8e43861943d175076e4b365039c8d5cd
func RunAdminCommandAsLoggedInUser() {
	log.Printf("before interactive user token")
	token, err := InteractiveUserToken(1 * time.Minute)
	if err != nil {
		log.Fatalf("InteractiveUserToken error: %v", err)
	}
	defer windows.CloseHandle(token)

	log.Printf("interactive user token ok")
/*	linkedToken, err := GetElevatedUserToken(token)
	if err != nil {
		log.Fatalf("GetElevatedUserToken error: %v", err)
	}
	defer windows.CloseHandle(linkedToken)*/

	log.Printf("elevated user token ok")
	//ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	//defer cancel()
	exepath, _ := osext.Executable()
	cmd := exec.Command(exepath, `gui`)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// creationFlags := uint32(CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE | CREATE_BREAKAWAY_FROM_JOB)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Token: syscall.Token(token),
		Token: syscall.Token(token),
		// CreationFlags: creationFlags,
	}
	log.Printf("prestart")
	err = cmd.Start()
	log.Printf("start ok")
	if err != nil {
		log.Fatalf("cmd start error: %v", err)
	}
	log.Printf("Waiting for command to finish...")
	err = cmd.Wait()
	log.Printf("RunAdminCommandAsLoggedInUser (gui) finished with error: %v", err)
}

// InteractiveUserToken returns a user token (security context) for the
// interactive desktop session attached to the default console (i.e. what would
// be seen on a display connected directly to the computer, rather than a
// remote RDP session). It must be called from a process which is running under
// LocalSystem account in order to have the necessary privileges (typically a
// Windows service). Since the service might be running before a local logon
// occurs, a timeout can be specified for waiting for a successful logon (via
// winlogon) to occur.  The returned token can be used in e.g.
// CreateProcessAsUser system call, which allows e.g. a Windows service to run
// a process in the interactive desktop session, as if the logged in user had
// executed the process directly. The function additionally waits for the user
// profile directory to exist, before returning.
func InteractiveUserToken(timeout time.Duration) (hToken windows.Handle, err error) {
	deadline := time.Now().Add(timeout)
	var sessionId uint32
	log.Printf("before interactive user token --1")
	sessionId, err = WTSGetActiveConsoleSessionId()
	log.Printf("before interactive user token --2")
	if err == nil {
		log.Printf("before interactive user token --3")
		err = WTSQueryUserToken(sessionId, &hToken)
		log.Printf("before interactive user token --4")
	}
	for err != nil {
		log.Printf("Error while InteactiveUserToken: %v", err)
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(time.Second / 10)
		sessionId, err = WTSGetActiveConsoleSessionId()
		if err == nil {
			err = WTSQueryUserToken(sessionId, &hToken)
		}
	}
	// to be safe, let's make sure profile directory has already been created,
	// to avoid likely race conditions outside of this function
	var userProfileDir string
	userProfileDir, err = ProfileDirectory(hToken)
	log.Printf("current interactive user, userProfileDir: %s, %v", userProfileDir, err)
	if err == nil {
		_, err = os.Stat(userProfileDir)
	}
	for err != nil {
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(time.Second / 10)
		userProfileDir, err = ProfileDirectory(hToken)
		log.Printf("current interactive user, userProfileDir: %s, %v", userProfileDir, err)
		if err == nil {
			_, err = os.Stat(userProfileDir)
		}
	}
	return
}

// ProfileDirectory returns the profile directory of the user represented by
// the given user handle
func ProfileDirectory(hToken windows.Handle) (string, error) {
	lpcchSize := uint32(0)
	GetUserProfileDirectory(hToken, nil, &lpcchSize)
	u16 := make([]uint16, lpcchSize)
	err := GetUserProfileDirectory(hToken, &u16[0], &lpcchSize)
	// bad token?
	if err != nil {
		return "", err
	}
	return syscall.UTF16ToString(u16), nil
}

func GetElevatedUserToken(hToken windows.Handle) (windows.Handle, error) {
	tokenInformationLength := uint32(1024)
	tokenInformation := make([]byte, tokenInformationLength)
	// TODO check for this https://www.remkoweijnen.nl/blog/2011/08/11/programmatically-check-if-user-account-control-is-enabled/
	err := GetTokenInformation(hToken, windows.TokenLinkedToken, &tokenInformation[0], tokenInformationLength, &tokenInformationLength)
	if err != nil {
		return 0, err
	}
	linkedTokenStruct := (*TOKEN_LINKED_TOKEN)(unsafe.Pointer(&tokenInformation[0]))
	return linkedTokenStruct.LinkedToken, nil
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/bb530719(v=vs.85).aspx
// typedef struct _TOKEN_LINKED_TOKEN {
//   HANDLE LinkedToken;
// } TOKEN_LINKED_TOKEN, *PTOKEN_LINKED_TOKEN;
type TOKEN_LINKED_TOKEN struct {
	LinkedToken windows.Handle // HANDLE
}

type TOKEN_USER struct {
	User windows.SIDAndAttributes
}

func GetTokenUser(hToken windows.Handle) (*windows.SID, error) {
	tokenInformationLength := uint32(0)
	_ = GetTokenInformation(hToken, windows.TokenUser, nil, 0, &tokenInformationLength)
	tokenInformation := make([]byte, tokenInformationLength)
	// TODO check for this https://www.remkoweijnen.nl/blog/2011/08/11/programmatically-check-if-user-account-control-is-enabled/
	// todo allocate memory from the begining
	err := GetTokenInformation(hToken, windows.TokenUser, &tokenInformation[0], tokenInformationLength, &tokenInformationLength)
	if err != nil {
		return nil, err
	}
	tokenUserStruct := (*TOKEN_USER)(unsafe.Pointer(&tokenInformation[0]))
	return tokenUserStruct.User.Sid, nil
}

func GetUserSid() (sid *windows.SID, err error) {
	var hToken windows.Token
	if err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &hToken); err != nil {
		if err == windows.ERROR_NO_TOKEN {
			if err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &hToken); err != nil {
				return
			}
		} else {
			return
		}
	}
	defer windows.CloseHandle(windows.Handle(hToken))

	sid, err = GetTokenUser(windows.Handle(hToken))

	return
}



// WTSConnectState enum type - Go version of WTS_CONNECTSTATE_CLASS
type WTSConnectStateEnum uint32

const (
	WTSConnectStateActive       WTSConnectStateEnum = WTSActive
	WTSConnectStateConnected    WTSConnectStateEnum = WTSConnected
	WTSConnectStateConnectQuery WTSConnectStateEnum = WTSConnectQuery
	WTSConnectStateShadow       WTSConnectStateEnum = WTSShadow
	WTSConnectStateDisconnected WTSConnectStateEnum = WTSDisconnected
	WTSConnectStateIdle         WTSConnectStateEnum = WTSIdle
	WTSConnectStateListen       WTSConnectStateEnum = WTSListen
	WTSConnectStateReset        WTSConnectStateEnum = WTSReset
	WTSConnectStateDown         WTSConnectStateEnum = WTSDown
	WTSConnectStateInit         WTSConnectStateEnum = WTSInit
)

// WTSClientProtocolType enum type go version of WTSClientProtocolType
type WTSClientProtocolTypeEnum uint32

const (
	WTSClientProtocolConsoleSession WTSClientProtocolTypeEnum = 0
	WTSClientProtocolInternal       WTSClientProtocolTypeEnum = 1
	WTSClientProtocolRDP            WTSClientProtocolTypeEnum = 2
)


type AddressFamily uint32

const (
	AddressFamilyUnspecified AddressFamily = wrappers.AF_UNSPEC
	AddressFamilyIP          AddressFamily = wrappers.AF_INET
	AddressFamilyIPX         AddressFamily = wrappers.AF_IPX
	AddressFamilyAppleTalk   AddressFamily = wrappers.AF_APPLETALK
	AddressFamilyNetBIOS     AddressFamily = wrappers.AF_NETBIOS
	AddressFamilyIPv6        AddressFamily = wrappers.AF_INET6
	AddressFamilyIrDA        AddressFamily = wrappers.AF_IRDA
	AddressFamilyBluetooth   AddressFamily = wrappers.AF_BTH
)

// WTSClientInfoStruct - go version of WTSCLIENT structure
type WTSClientInfoStruct struct {
	ClientName          string
	Domain              string
	UserName            string
	WorkDirectory       string
	InitialProgram      string
	EncryptionLevel     byte
	ClientAddressFamily AddressFamily
	clientAddress       [wrappers.CLIENTADDRESS_LENGTH + 1]uint16
	HRes                uint
	VRes                uint
	ColorDepth          uint
	ClientDirectory     string
	ClientBuildNumber   uint
	ClientHardwareId    uint
	ClientProductId     uint
	OutBufCountHost     uint
	OutBufCountClient   uint
	OutBufLength        uint
	DeviceID            string
}

func (ci *WTSClientInfoStruct) ClientAddressToIP() (net.IP, error) {
	var buf [16]byte
	for i := 0; i < 16; i++ {
		buf[i] = byte(ci.clientAddress[i])
	}
	return clientAddressToIP(uint32(ci.ClientAddressFamily), buf[:])
}

// WTSClientDisplayStruct - go version of WTS_CLIENT_DISPLAY structure
type WTSClientDisplayStruct struct {
	HorizontalResolution uint
	VerticalResolution   uint
	ColorDepth           uint
}

// Info - go version of WTSINFO structure
type WTSInfo struct {
	State                   WTSConnectStateEnum
	SessionID               uint
	IncomingBytes           uint
	OutgoingBytes           uint
	IncomingFrames          uint
	OutgoingFrames          uint
	IncomingCompressedBytes uint
	OutgoingCompressedBytes uint
	WinStationName          string
	Domain                  string
	UserName                string
	ConnectTime             time.Time
	DisconnectTime          time.Time
	LastInputTime           time.Time
	LogonTime               time.Time
	CurrentTime             time.Time
}

// WTSSessionInfoStruct - go version of WTS_SESSION_INFO structure
type WTSSessionInfoStruct struct {
	SessionID      uint
	WinStationName string
	State          WTSConnectStateEnum
}

type WTSServer struct {
	handle syscall.Handle
}

func OpenWTSServer(serverName string) *WTSServer {
	result := WTSServer{}
	if serverName != "" {
		result.handle = wrappers.WTSOpenServer(syscall.StringToUTF16Ptr(serverName))
	}
	return &result
}

func (wts *WTSServer) Close() {
	if wts.handle != 0 {
		wrappers.WTSCloseServer(wts.handle)
		wts.handle = 0
	}
}

func (wts *WTSServer) EnumerateSessions() ([]WTSSessionInfoStruct, error) {
	var sessionInfo *wrappers.WTS_SESSION_INFO
	var count uint32

	if err := wrappers.WTSEnumerateSessions(wts.handle, 0, 1, &sessionInfo, &count); err != nil {
		return nil, err
	}
	defer wrappers.WTSFreeMemory((*byte)(unsafe.Pointer(sessionInfo)))

	si := sessionInfo
	result := make([]WTSSessionInfoStruct, count)
	for i := uint32(0); i < count; i++ {
		result[i] = WTSSessionInfoStruct{SessionID: uint(si.SessionId),
			WinStationName: LpstrToString(si.WinStationName),
			State:          WTSConnectStateEnum(si.State)}
		si = (*wrappers.WTS_SESSION_INFO)(unsafe.Pointer(uintptr(unsafe.Pointer(si)) + unsafe.Sizeof(*si)))
	}
	return result, nil
}

func (wts *WTSServer) LogoffSession(sessionID uint, wait bool) error {
	return wrappers.WTSLogoffSession(wts.handle, uint32(sessionID), wait)
}

func (wts *WTSServer) QuerySessionInitialProgram(sessionID uint) (string, error) {
	return wts.querySessionInformationAsString(sessionID, wrappers.WTSInitialProgram)
}

func (wts *WTSServer) QuerySessionApplicationName(sessionID uint) (string, error) {
	return wts.querySessionInformationAsString(sessionID, wrappers.WTSApplicationName)
}

func (wts *WTSServer) QuerySessionWorkingDirectory(sessionID uint) (string, error) {
	return wts.querySessionInformationAsString(sessionID, wrappers.WTSWorkingDirectory)
}

func (wts *WTSServer) QuerySessionID(sessionID uint) (uint, error) {
	r1, err := wts.querySessionInformationAsUint32(sessionID, wrappers.WTSSessionId)
	return uint(r1), err
}

func (wts *WTSServer) QuerySessionUserName(sessionID uint) (string, error) {
	return wts.querySessionInformationAsString(sessionID, wrappers.WTSUserName)
}

func (wts *WTSServer) QuerySessionWinStationName(sessionID uint) (string, error) {
	return wts.querySessionInformationAsString(sessionID, wrappers.WTSWinStationName)
}

func (wts *WTSServer) QuerySessionDomainName(sessionID uint) (string, error) {
	return wts.querySessionInformationAsString(sessionID, wrappers.WTSDomainName)
}

func (wts *WTSServer) QuerySessionConnectState(sessionID uint) (WTSConnectStateEnum, error) {
	r1, err := wts.querySessionInformationAsUint32(sessionID, wrappers.WTSConnectState)
	return WTSConnectStateEnum(r1), err
}

func (wts *WTSServer) QuerySessionClientBuildNumber(sessionID uint) (uint32, error) {
	return wts.querySessionInformationAsUint32(sessionID, wrappers.WTSClientBuildNumber)
}

func (wts *WTSServer) QuerySessionClientName(sessionID uint) (string, error) {
	return wts.querySessionInformationAsString(sessionID, wrappers.WTSClientName)
}

func (wts *WTSServer) QuerySessionClientDirectory(sessionID uint) (string, error) {
	return wts.querySessionInformationAsString(sessionID, wrappers.WTSClientDirectory)
}

func (wts *WTSServer) QuerySessionClientProductId(sessionID uint) (uint16, error) {
	return wts.querySessionInformationAsUint16(sessionID, wrappers.WTSClientProductId)
}

func (wts *WTSServer) QuerySessionClientHardwareId(sessionID uint) (uint32, error) {
	return wts.querySessionInformationAsUint32(sessionID, wrappers.WTSClientHardwareId)
}

func (wts *WTSServer) QuerySessionClientAddress(sessionID uint) (net.IP, error) {
	var buffer *uint16
	var bytesReturned uint32

	if err := wrappers.WTSQuerySessionInformation(wts.handle, uint32(sessionID), wrappers.WTSClientAddress, &buffer, &bytesReturned); err != nil {
		return net.IP{}, err
	}
	defer wrappers.WTSFreeMemory((*byte)(unsafe.Pointer(buffer)))

	// MS doc: The IP address is offset by two bytes from the start of the Address member of the WTS_CLIENT_ADDRESS structure.
	// https://msdn.microsoft.com/en-us/library/aa383861%28v=vs.85%29.aspx
	a := *(*wrappers.WTS_CLIENT_ADDRESS)(unsafe.Pointer(buffer))
	return clientAddressToIP(a.AddressFamily, a.Address[2:])
}

func (wts *WTSServer) QuerySessionClientDisplay(sessionID uint) (WTSClientDisplayStruct, error) {
	var buffer *uint16
	var bytesReturned uint32

	if err := wrappers.WTSQuerySessionInformation(wts.handle, uint32(sessionID), wrappers.WTSClientDisplay, &buffer, &bytesReturned); err != nil {
		return WTSClientDisplayStruct{}, err
	}
	defer wrappers.WTSFreeMemory((*byte)(unsafe.Pointer(buffer)))

	cd := *(*wrappers.WTS_CLIENT_DISPLAY)(unsafe.Pointer(buffer))
	return WTSClientDisplayStruct{
		HorizontalResolution: uint(cd.HorizontalResolution),
		VerticalResolution:   uint(cd.HorizontalResolution),
		ColorDepth:           uint(cd.ColorDepth)}, nil
}

func (wts *WTSServer) QuerySessionClientProtocolType(sessionID uint) (WTSClientProtocolTypeEnum, error) {
	r1, err := wts.querySessionInformationAsUint16(sessionID, wrappers.WTSClientProtocolType)
	return WTSClientProtocolTypeEnum(r1), err
}

func (wts *WTSServer) QuerySessionClientInfo(sessionID uint) (WTSClientInfoStruct, error) {
	var buffer *uint16
	var bytesReturned uint32

	if err := wrappers.WTSQuerySessionInformation(wts.handle, uint32(sessionID), wrappers.WTSClientInfo, &buffer, &bytesReturned); err != nil {
		return WTSClientInfoStruct{}, err
	}
	defer wrappers.WTSFreeMemory((*byte)(unsafe.Pointer(buffer)))

	c := *(*wrappers.WTSCLIENT)(unsafe.Pointer(buffer))
	return WTSClientInfoStruct{
		ClientName:          syscall.UTF16ToString(c.ClientName[:]),
		Domain:              syscall.UTF16ToString(c.Domain[:]),
		UserName:            syscall.UTF16ToString(c.UserName[:]),
		WorkDirectory:       syscall.UTF16ToString(c.WorkDirectory[:]),
		InitialProgram:      syscall.UTF16ToString(c.InitialProgram[:]),
		EncryptionLevel:     c.EncryptionLevel,
		ClientAddressFamily: AddressFamily(c.ClientAddressFamily),
		clientAddress:       c.ClientAddress,
		HRes:                uint(c.HRes),
		VRes:                uint(c.VRes),
		ColorDepth:          uint(c.ColorDepth),
		ClientDirectory:     syscall.UTF16ToString(c.ClientDirectory[:]),
		ClientBuildNumber:   uint(c.ClientBuildNumber),
		ClientHardwareId:    uint(c.ClientHardwareId),
		ClientProductId:     uint(c.ClientProductId),
		OutBufCountHost:     uint(c.OutBufCountHost),
		OutBufCountClient:   uint(c.OutBufCountClient),
		OutBufLength:        uint(c.OutBufLength),
		DeviceID:            syscall.UTF16ToString(c.DeviceId[:]),
	}, nil
}

func (wts *WTSServer) QuerySessionSesionInfo(sessionID uint) (WTSInfo, error) {
	var buffer *uint16
	var bytesReturned uint32

	if err := wrappers.WTSQuerySessionInformation(wts.handle, uint32(sessionID), wrappers.WTSSessionInfo, &buffer, &bytesReturned); err != nil {
		return WTSInfo{}, err
	}
	defer wrappers.WTSFreeMemory((*byte)(unsafe.Pointer(buffer)))

	i := *(*wrappers.WTSINFO)(unsafe.Pointer(buffer))
	return WTSInfo{
		State:                   WTSConnectStateEnum(i.State),
		SessionID:               uint(i.SessionId),
		IncomingBytes:           uint(i.IncomingBytes),
		OutgoingBytes:           uint(i.OutgoingBytes),
		IncomingFrames:          uint(i.IncomingFrames),
		OutgoingFrames:          uint(i.OutgoingFrames),
		IncomingCompressedBytes: uint(i.IncomingCompressedBytes),
		OutgoingCompressedBytes: uint(i.OutgoingCompressedBytes),
		WinStationName:          syscall.UTF16ToString(i.WinStationName[:]),
		Domain:                  syscall.UTF16ToString(i.Domain[:]),
		UserName:                syscall.UTF16ToString(i.UserName[:]),
		ConnectTime:             windowsFileTimeToTime(i.ConnectTime),
		DisconnectTime:          windowsFileTimeToTime(i.DisconnectTime),
		LastInputTime:           windowsFileTimeToTime(i.LastInputTime),
		LogonTime:               windowsFileTimeToTime(i.LogonTime),
		CurrentTime:             windowsFileTimeToTime(i.CurrentTime)}, nil
}

func (wts *WTSServer) QuerySessionAddressV4(sessionID uint) (wrappers.WTS_CLIENT_ADDRESS, error) {
	var buffer *uint16
	var bytesReturned uint32

	if err := wrappers.WTSQuerySessionInformation(wts.handle, uint32(sessionID), wrappers.WTSSessionAddressV4, &buffer, &bytesReturned); err != nil {
		return wrappers.WTS_CLIENT_ADDRESS{}, err
	}
	defer wrappers.WTSFreeMemory((*byte)(unsafe.Pointer(buffer)))

	return *(*wrappers.WTS_CLIENT_ADDRESS)(unsafe.Pointer(buffer)), nil
}

func (wts *WTSServer) QuerySessionIsRemoteSession(sessionID uint) (bool, error) {
	return wts.querySessionInformationAsBool(sessionID, wrappers.WTSIsRemoteSession)
}

func (wts *WTSServer) QueryUserToken(sessionID uint) (*syscall.Handle, error) {
	var handle syscall.Handle
	if err := wrappers.WTSQueryUserToken(uint32(sessionID), &handle); err != nil {
		return nil, err
	}
	return &handle, nil
}

func (wts *WTSServer) querySessionInformationAsBool(sessionID uint, infoClass uint32) (bool, error) {
	var buffer *uint16
	var bytesReturned uint32

	if err := wrappers.WTSQuerySessionInformation(wts.handle, uint32(sessionID), infoClass, &buffer, &bytesReturned); err != nil {
		return false, err
	}
	defer wrappers.WTSFreeMemory((*byte)(unsafe.Pointer(buffer)))

	if bytesReturned != 1 {
		return false, buferSizeError(1, bytesReturned)
	}

	return *(*byte)(unsafe.Pointer(buffer)) != 0, nil
}

func (wts *WTSServer) querySessionInformationAsString(sessionID uint, infoClass uint32) (string, error) {
	var buffer *uint16
	var bytesReturned uint32

	if err := wrappers.WTSQuerySessionInformation(wts.handle, uint32(sessionID), infoClass, &buffer, &bytesReturned); err != nil {
		return "", err
	}
	defer wrappers.WTSFreeMemory((*byte)(unsafe.Pointer(buffer)))

	return LpstrToString(buffer), nil
}

func (wts *WTSServer) querySessionInformationAsUint16(sessionID uint, infoClass uint32) (uint16, error) {
	var buffer *uint16
	var bytesReturned uint32

	if err := wrappers.WTSQuerySessionInformation(wts.handle, uint32(sessionID), infoClass, &buffer, &bytesReturned); err != nil {
		return 0, err
	}
	defer wrappers.WTSFreeMemory((*byte)(unsafe.Pointer(buffer)))

	if bytesReturned != 2 {
		return 0, buferSizeError(2, bytesReturned)
	}
	return *(*uint16)(unsafe.Pointer(buffer)), nil
}

func (wts *WTSServer) querySessionInformationAsUint32(sessionID uint, infoClass uint32) (uint32, error) {
	var buffer *uint16
	var bytesReturned uint32

	if err := wrappers.WTSQuerySessionInformation(wts.handle, uint32(sessionID), infoClass, &buffer, &bytesReturned); err != nil {
		return 0, err
	}
	defer wrappers.WTSFreeMemory((*byte)(unsafe.Pointer(buffer)))

	if bytesReturned != 4 {
		return 0, buferSizeError(4, bytesReturned)
	}
	return *(*uint32)(unsafe.Pointer(buffer)), nil
}

func buferSizeError(excpected, returned uint32) error {
	return fmt.Errorf("Invalid buffer size. Expected: %d returned: %d", excpected, returned)
}

func clientAddressToIP(addressFamily uint32, address []byte) (net.IP, error) {
	switch addressFamily {
	case wrappers.AF_INET:
		if len(address) >= 4 {
			return net.IPv4(address[0], address[1], address[2], address[3]), nil
		}
	case wrappers.AF_INET6:
		if len(address) >= 16 {
			return net.IP(address[:16]), nil
		}
	}
	return nil, fmt.Errorf("Unknown addressFamily: %v", addressFamily)
}

func windowsFileTimeToTime(fileTime int64) time.Time {
	const TicksPerSecond = 10000000
	const EpochDifference = 11644473600
	// we also can use win32 api FileTimeToSystemTime
	return time.Unix((fileTime/TicksPerSecond)-EpochDifference, 0)
}


