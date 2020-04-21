// Copyright 2015 Daniel Theophanes.
// Use of this source code is governed by a zlib-style
// license that can be found in the LICENSE file.

package service

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

const version = "windows-service"

type WindowsEvent struct {
	MsgId     svc.Cmd
	MsgType   uint32
	SessionId uint32
	SID       *windows.SID

}

func (w *WindowsEvent) String() string {
	sid := w.SID.String()

	return fmt.Sprintf(
		`MsgId=%s, MsgType=%s [session=%d, sid=%s]`,
		CmdToString(w.MsgId),
		MsgTypeToString(w.MsgType),
		w.SessionId,
		sid,
		)
}

const (
	WTS_CONSOLE_CONNECT = 0x1
	WTS_CONSOLE_DISCONNECT     = 0x2
	WTS_REMOTE_CONNECT         = 0x3
	WTS_REMOTE_DISCONNECT      = 0x4
	WTS_SESSION_LOGON          = 0x5
	WTS_SESSION_LOGOFF         = 0x6
	WTS_SESSION_LOCK           = 0x7
	WTS_SESSION_UNLOCK         = 0x8
	WTS_SESSION_REMOTE_CONTROL = 0x9
	WTS_SESSION_CREATE         = 0xA
	WTS_SESSION_TERMINATE      = 0xB
)

func MsgTypeToString(msgType uint32) string {
	switch msgType {
	case WTS_CONSOLE_CONNECT: return "WTS_CONSOLE_CONNECT"
	case WTS_CONSOLE_DISCONNECT: return "WTS_CONSOLE_DISCONNECT"
	case WTS_REMOTE_CONNECT: return "WTS_REMOTE_CONNECT"
	case WTS_REMOTE_DISCONNECT: return "WTS_REMOTE_DISCONNECT"
	case WTS_SESSION_LOGON: return "WTS_SESSION_LOGON"
	case WTS_SESSION_LOGOFF: return "WTS_SESSION_LOGOFF"
	case WTS_SESSION_LOCK: return "WTS_SESSION_LOCK"
	case WTS_SESSION_UNLOCK: return "WTS_SESSION_UNLOCK"
	case WTS_SESSION_REMOTE_CONTROL: return "WTS_SESSION_REMOTE_CONTROL"
	case WTS_SESSION_CREATE: return "WTS_SESSION_CREATE"
	case WTS_SESSION_TERMINATE: return "WTS_SESSION_TERMINATE"
	default: return "Unknown"
	}
}

func CmdToString(id svc.Cmd) string {
	switch id {
	case svc.SessionChange: return "SessionChange"
	case svc.Stop: return "Stop"
	case svc.Pause: return "Pause"
	case svc.Continue: return "Continue"
	case svc.Interrogate: return "Interrogate"
	default:
		return "Unknown"

		//Shutdown              = Cmd(windows.SERVICE_CONTROL_SHUTDOWN)
		//ParamChange           = Cmd(windows.SERVICE_CONTROL_PARAMCHANGE)
		//NetBindAdd            = Cmd(windows.SERVICE_CONTROL_NETBINDADD)
		//NetBindRemove         = Cmd(windows.SERVICE_CONTROL_NETBINDREMOVE)
		//NetBindEnable         = Cmd(windows.SERVICE_CONTROL_NETBINDENABLE)
		//NetBindDisable        = Cmd(windows.SERVICE_CONTROL_NETBINDDISABLE)
		//DeviceEvent           = Cmd(windows.SERVICE_CONTROL_DEVICEEVENT)
		//HardwareProfileChange = Cmd(windows.SERVICE_CONTROL_HARDWAREPROFILECHANGE)
		//PowerEvent            = Cmd(windows.SERVICE_CONTROL_POWEREVENT)
		//SessionChange         = Cmd(windows.SERVICE_CONTROL_SESSIONCHANGE)

	}
}


type windowsService struct {
	i Interface
	*Config

	errSync      sync.Mutex
	stopStartErr error

	ExtraEventsChannel chan WindowsEvent
}

// WindowsLogger allows using windows specific logging methods.
type WindowsLogger struct {
	ev   *eventlog.Log
	errs chan<- error
}

type windowsSystem struct{}

func (windowsSystem) String() string {
	return version
}
func (windowsSystem) Detect() bool {
	return true
}
func (windowsSystem) Interactive() bool {
	return interactive
}
func (windowsSystem) New(i Interface, c *Config) (Service, error) {
	ws := &windowsService{
		i:      i,
		Config: c,
		ExtraEventsChannel: c.WindowsExtraEvents,
	}
	return ws, nil
}

func init() {
	ChooseSystem(windowsSystem{})
}

func (l WindowsLogger) send(err error) error {
	if err == nil {
		return nil
	}
	if l.errs != nil {
		l.errs <- err
	}
	return err
}

// Error logs an error message.
func (l WindowsLogger) Error(v ...interface{}) error {
	return l.send(l.ev.Error(3, fmt.Sprint(v...)))
}

// Warning logs an warning message.
func (l WindowsLogger) Warning(v ...interface{}) error {
	return l.send(l.ev.Warning(2, fmt.Sprint(v...)))
}

// Info logs an info message.
func (l WindowsLogger) Info(v ...interface{}) error {
	return l.send(l.ev.Info(1, fmt.Sprint(v...)))
}

// Errorf logs an error message.
func (l WindowsLogger) Errorf(format string, a ...interface{}) error {
	return l.send(l.ev.Error(3, fmt.Sprintf(format, a...)))
}

// Warningf logs an warning message.
func (l WindowsLogger) Warningf(format string, a ...interface{}) error {
	return l.send(l.ev.Warning(2, fmt.Sprintf(format, a...)))
}

// Infof logs an info message.
func (l WindowsLogger) Infof(format string, a ...interface{}) error {
	return l.send(l.ev.Info(1, fmt.Sprintf(format, a...)))
}

// NError logs an error message and an event ID.
func (l WindowsLogger) NError(eventID uint32, v ...interface{}) error {
	return l.send(l.ev.Error(eventID, fmt.Sprint(v...)))
}

// NWarning logs an warning message and an event ID.
func (l WindowsLogger) NWarning(eventID uint32, v ...interface{}) error {
	return l.send(l.ev.Warning(eventID, fmt.Sprint(v...)))
}

// NInfo logs an info message and an event ID.
func (l WindowsLogger) NInfo(eventID uint32, v ...interface{}) error {
	return l.send(l.ev.Info(eventID, fmt.Sprint(v...)))
}

// NErrorf logs an error message and an event ID.
func (l WindowsLogger) NErrorf(eventID uint32, format string, a ...interface{}) error {
	return l.send(l.ev.Error(eventID, fmt.Sprintf(format, a...)))
}

// NWarningf logs an warning message and an event ID.
func (l WindowsLogger) NWarningf(eventID uint32, format string, a ...interface{}) error {
	return l.send(l.ev.Warning(eventID, fmt.Sprintf(format, a...)))
}

// NInfof logs an info message and an event ID.
func (l WindowsLogger) NInfof(eventID uint32, format string, a ...interface{}) error {
	return l.send(l.ev.Info(eventID, fmt.Sprintf(format, a...)))
}

var interactive = false

func init() {
	var err error
	interactive, err = svc.IsAnInteractiveSession()
	if err != nil {
		panic(err)
	}
}

func (ws *windowsService) String() string {
	if len(ws.DisplayName) > 0 {
		return ws.DisplayName
	}
	return ws.Name
}

func (ws *windowsService) Platform() string {
	return version
}

func (ws *windowsService) setError(err error) {
	ws.errSync.Lock()
	defer ws.errSync.Unlock()
	ws.stopStartErr = err
}
func (ws *windowsService) getError() error {
	ws.errSync.Lock()
	defer ws.errSync.Unlock()
	return ws.stopStartErr
}

const WTS_CURRENT_SERVER_HANDLE = 0

func (ws *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	cmdsAccepted := svc.AcceptStop | svc.AcceptShutdown

	if ws.ExtraEventsChannel != nil {
		cmdsAccepted |= svc.AcceptNetBindChange | svc.AcceptHardwareProfileChange | svc.AcceptSessionChange
		defer close(ws.ExtraEventsChannel)
	}

	changes <- svc.Status{State: svc.StartPending}

	if err := ws.i.Start(ws); err != nil {
		ws.setError(err)
		return true, 1
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
loop:
	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			if err := ws.i.Stop(ws); err != nil {
				ws.setError(err)
				return true, 2
			}
			break loop
		case svc.SessionChange:
			if ws.ExtraEventsChannel == nil {
				continue loop
			}

			// c.EventType can be WTS_CONSOLE_CONNECT, WTS_REMOTE_CONNECT, WTS_SESSION_LOGON, etc....

			// https://docs.microsoft.com/en-us/windows/win32/termserv/wm-wtssession-change
			//if c.EventType != windows.WTS_SESSION_LOGON && c.EventType != windows.WTS_SESSION_LOGOFF {
			//	continue
			//}
			//
			//defaultWTSServer := &gowin32.WTSServer{
			//	WTS_CURRENT_SERVER_HANDLE,
			//}

			sessionNotification := (*WTSSESSION_NOTIFICATION)(unsafe.Pointer(c.EventData))
			if uintptr(sessionNotification.Size) != unsafe.Sizeof(*sessionNotification) {
				log.Printf("Unexpected size of WTSSESSION_NOTIFICATION: %d", sessionNotification.Size)
				continue
			}
			sessionId := sessionNotification.SessionId

			wts := OpenWTSServer("")
			inf, err := wts.QuerySessionSesionInfo(uint(sessionId))
			log.Printf("%v, %v", inf, err)


			//if c.EventType == windows.WTS_SESSION_LOGOFF {
			//	procsLock.Lock()
			//	delete(aliveSessions, sessionNotification.SessionID)
			//	if proc, ok := procs[sessionNotification.SessionID]; ok {
			//		proc.Kill()
			//	}
			//	procsLock.Unlock()
			//} else if c.EventType == windows.WTS_SESSION_LOGON {
			//	procsLock.Lock()
			//	if alive := aliveSessions[sessionNotification.SessionID]; !alive {
			//		aliveSessions[sessionNotification.SessionID] = true
			//		if _, ok := procs[sessionNotification.SessionID]; !ok {
			//			goStartProcess(sessionNotification.SessionID)
			//		}
			//	}
			//	procsLock.Unlock()
			//}

			var hToken windows.Handle
			err = WTSQueryUserToken(sessionId, &hToken)
			if err != nil {
				log.Printf("ERROR ERROR (session:%d): %v", sessionId, err)
				continue
			}
			defer windows.CloseHandle(hToken)

			sid, err := GetTokenUser(windows.Handle(hToken))
			if err != nil {
				log.Printf("ERROR ERROR2 (session:%d): %v", sessionId, err)
				continue
			}

			ws.ExtraEventsChannel <- WindowsEvent{
				MsgId: c.Cmd,
				MsgType: c.EventType,
				SessionId: sessionNotification.SessionId,
				SID: sid,
			}

			if (c.Cmd == 14 && c.Cmd == 5) {
				log.Printf("running command as new user")
				//go winsessions.RunAdminCommandAsLoggedInUser(hToken)
				log.Printf("done run command")
			}
		default:
			continue loop
		}
	}

	return false, 0
}

func (ws *windowsService) Install() error {
	exepath, err := ws.execPath()
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ws.Name)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", ws.Name)
	}
	s, err = m.CreateService(ws.Name, exepath, mgr.Config{
		DisplayName:      ws.DisplayName,
		Description:      ws.Description,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: ws.UserName,
		Password:         ws.Option.string("Password", ""),
		Dependencies:     ws.Dependencies,
	}, ws.Arguments...)
	if err != nil {
		return err
	}
	defer s.Close()
	err = eventlog.InstallAsEventCreate(ws.Name, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		if !strings.Contains(err.Error(), "exists") {
			s.Delete()
			return fmt.Errorf("SetupEventLogSource() failed: %s", err)
		}
	}
	return nil
}

func (ws *windowsService) Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ws.Name)
	if err != nil {
		return fmt.Errorf("service %s is not installed", ws.Name)
	}
	defer s.Close()
	err = s.Delete()
	if err != nil {
		return err
	}
	err = eventlog.Remove(ws.Name)
	if err != nil {
		return fmt.Errorf("RemoveEventLogSource() failed: %s", err)
	}
	return nil
}

func (ws *windowsService) Run() error {
	ws.setError(nil)
	if !interactive {
		// Return error messages from start and stop routines
		// that get executed in the Execute method.
		// Guarded with a mutex as it may run a different thread
		// (callback from windows).
		runErr := svc.Run(ws.Name, ws)
		startStopErr := ws.getError()
		if startStopErr != nil {
			return startStopErr
		}
		if runErr != nil {
			return runErr
		}
		return nil
	}
	err := ws.i.Start(ws)
	if err != nil {
		return err
	}

	sigChan := make(chan os.Signal)

	signal.Notify(sigChan, os.Interrupt)

	<-sigChan

	return ws.i.Stop(ws)
}

func (ws *windowsService) Status() (Status, error) {
	m, err := mgr.Connect()
	if err != nil {
		return StatusUnknown, err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ws.Name)
	if err != nil {
		if err.Error() == "The specified service does not exist as an installed service." {
			return StatusUnknown, ErrNotInstalled
		}
		return StatusUnknown, err
	}

	status, err := s.Query()
	if err != nil {
		return StatusUnknown, err
	}

	switch status.State {
	case svc.StartPending:
		fallthrough
	case svc.Running:
		return StatusRunning, nil
	case svc.PausePending:
		fallthrough
	case svc.Paused:
		fallthrough
	case svc.ContinuePending:
		fallthrough
	case svc.StopPending:
		fallthrough
	case svc.Stopped:
		return StatusStopped, nil
	default:
		return StatusUnknown, fmt.Errorf("unknown status %v", status)
	}
}

func (ws *windowsService) Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ws.Name)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

func (ws *windowsService) Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ws.Name)
	if err != nil {
		return err
	}
	defer s.Close()

	return ws.stopWait(s)
}

func (ws *windowsService) Restart() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ws.Name)
	if err != nil {
		return err
	}
	defer s.Close()

	err = ws.stopWait(s)
	if err != nil {
		return err
	}

	return s.Start()
}

func (ws *windowsService) stopWait(s *mgr.Service) error {
	// First stop the service. Then wait for the service to
	// actually stop before starting it.
	status, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}

	timeDuration := time.Millisecond * 50

	timeout := time.After(getStopTimeout() + (timeDuration * 2))
	tick := time.NewTicker(timeDuration)
	defer tick.Stop()

	for status.State != svc.Stopped {
		select {
		case <-tick.C:
			status, err = s.Query()
			if err != nil {
				return err
			}
		case <-timeout:
			break
		}
	}
	return nil
}

// getStopTimeout fetches the time before windows will kill the service.
func getStopTimeout() time.Duration {
	// For default and paths see https://support.microsoft.com/en-us/kb/146092
	defaultTimeout := time.Millisecond * 20000
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, registry.READ)
	if err != nil {
		return defaultTimeout
	}
	sv, _, err := key.GetStringValue("WaitToKillServiceTimeout")
	if err != nil {
		return defaultTimeout
	}
	v, err := strconv.Atoi(sv)
	if err != nil {
		return defaultTimeout
	}
	return time.Millisecond * time.Duration(v)
}

func (ws *windowsService) Logger(errs chan<- error) (Logger, error) {
	if interactive {
		return ConsoleLogger, nil
	}
	return ws.SystemLogger(errs)
}
func (ws *windowsService) SystemLogger(errs chan<- error) (Logger, error) {
	el, err := eventlog.Open(ws.Name)
	if err != nil {
		return nil, err
	}
	return WindowsLogger{el, errs}, nil
}
