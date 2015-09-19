// Copyright 2015 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package overlord

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

type RegistrationFailedError error

const (
	LOG_BUFSIZ        = 1024 * 16
	PING_RECV_TIMEOUT = PING_TIMEOUT * 2
)

type TerminalControl struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

type LogcatContext struct {
	Format  int               // Log format, see constants.go
	WsConns []*websocket.Conn // WebSockets for logcat
	History string            // Log buffer for logcat
}

type FileDownloadContext struct {
	Name  string      // Download filename
	Size  int64       // Download filesize
	Data  chan []byte // Channel for download data
	Ready bool        // Ready for download
}

// Since Shell and Logcat are initiated by Overlord, there is only one observer,
// i.e. the one who requested the connection. On the other hand, logcat
// could have multiple observers, so we need to broadcast the result to all of
// them.
type ConnServer struct {
	*RPCCore
	Mode          int                    // Client mode, see constants.go
	Command       chan interface{}       // Channel for overlord command
	Response      chan string            // Channel for reponsing overlord command
	Sid           string                 // Session ID
	Mid           string                 // Machine ID
	TerminalSid   string                 // Associated terminal session ID
	Properties    map[string]interface{} // Client properties
	TargetSSHPort int                    // Target SSH port for forwarding
	ovl           *Overlord              // Overlord handle
	registered    bool                   // Whether we are registered or not
	wsConn        *websocket.Conn        // WebSocket for Terminal and Shell
	logcat        LogcatContext          // Logcat context
	Download      FileDownloadContext    // File download context
	stopListen    chan bool              // Stop the Listen() loop
	lastPing      int64                  // Last time the client pinged
}

func NewConnServer(ovl *Overlord, conn net.Conn) *ConnServer {
	return &ConnServer{
		RPCCore:    NewRPCCore(conn),
		Mode:       NONE,
		Command:    make(chan interface{}),
		Response:   make(chan string),
		Properties: make(map[string]interface{}),
		ovl:        ovl,
		stopListen: make(chan bool, 1),
		registered: false,
		Download:   FileDownloadContext{Data: make(chan []byte)},
	}
}

func (self *ConnServer) SetProperties(prop map[string]interface{}) {
	if prop != nil {
		self.Properties = prop
	}

	addr := self.Conn.RemoteAddr().String()
	parts := strings.Split(addr, ":")
	self.Properties["ip"] = strings.Join(parts[:len(parts)-1], ":")
}

func (self *ConnServer) StopListen() {
	self.stopListen <- true
}

func (self *ConnServer) Terminate() {
	if self.registered {
		self.ovl.Unregister(self)
	}
	if self.Conn != nil {
		self.Conn.Close()
	}
	if self.wsConn != nil {
		self.wsConn.WriteMessage(websocket.CloseMessage, []byte(""))
		self.wsConn.Close()
	}
}

// writeWebsocket is a helper function for written text to websocket in the
// correct format.
func (self *ConnServer) writeLogToWS(conn *websocket.Conn, buf string) error {
	if self.Mode == LOGCAT && self.logcat.Format == TEXT {
		buf = ToVTNewLine(buf)
	}
	return conn.WriteMessage(websocket.BinaryMessage, []byte(buf))
}

// Forwards the input from Websocket to TCP socket.
func (self *ConnServer) forwardWSInput(allowBinary bool) {
	defer func() {
		self.stopListen <- true
	}()

	for {
		mt, payload, err := self.wsConn.ReadMessage()
		if err != nil {
			if err == io.EOF {
				log.Println("WebSocket connection terminated")
			} else {
				log.Println("Unknown error while reading from WebSocket")
			}
			return
		}

		switch mt {
		case websocket.BinaryMessage:
			if allowBinary {
				self.Conn.Write(payload)
			} else {
				log.Printf("Ignoring binary message: %q\n", payload)
			}
		case websocket.TextMessage:
			self.Conn.Write(payload)
		default:
			log.Printf("Invalid message type %d\n", mt)
			return
		}
	}
	return
}

// Forward the PTY output to WebSocket.
func (self *ConnServer) forwardWSOutput(buffer string) {
	if self.wsConn == nil {
		self.stopListen <- true
	}
	self.wsConn.WriteMessage(websocket.BinaryMessage, []byte(buffer))
}

// Forward the logcat output to WebSocket.
func (self *ConnServer) forwardShellOutput(buffer string) {
	if self.wsConn == nil {
		self.stopListen <- true
	}
	self.writeLogToWS(self.wsConn, buffer)
}

// Forward the logcat output to WebSocket.
func (self *ConnServer) forwardLogcatOutput(buffer string) {
	self.logcat.History += buffer
	if l := len(self.logcat.History); l > LOG_BUFSIZ {
		self.logcat.History = self.logcat.History[l-LOG_BUFSIZ : l]
	}

	var aliveWsConns []*websocket.Conn
	for _, conn := range self.logcat.WsConns[:] {
		if err := self.writeLogToWS(conn, buffer); err == nil {
			aliveWsConns = append(aliveWsConns, conn)
		} else {
			conn.Close()
		}
	}
	self.logcat.WsConns = aliveWsConns
}

func (self *ConnServer) forwardFileDownloadData(buffer []byte) {
	self.Download.Data <- buffer
}

func (self *ConnServer) ProcessRequests(reqs []*Request) error {
	for _, req := range reqs {
		if err := self.handleRequest(req); err != nil {
			return err
		}
	}
	return nil
}

// Handle the requests from Overlord.
func (self *ConnServer) handleOverlordRequest(obj interface{}) {
	log.Printf("Received %T command from overlord\n", obj)
	switch v := obj.(type) {
	case SpawnTerminalCmd:
		self.SpawnTerminal(v.Sid, v.TtyDevice)
	case SpawnShellCmd:
		self.SpawnShell(v.Sid, v.Command)
	case ConnectLogcatCmd:
		// Write log history to newly joined client
		self.writeLogToWS(v.Conn, self.logcat.History)
		self.logcat.WsConns = append(self.logcat.WsConns, v.Conn)
	case SpawnFileCmd:
		self.SpawnFileServer(v.Sid, v.TerminalSid, v.Action, v.Filename)
	case SpawnForwarderCmd:
		self.SpawnForwarder(v.Sid, v.Port)
	}
}

// Main routine for listen to socket messages.
func (self *ConnServer) Listen() {
	var reqs []*Request
	readChan, readErrChan := self.SpawnReaderRoutine()
	ticker := time.NewTicker(time.Duration(TIMEOUT_CHECK_SECS * time.Second))

	defer self.Terminate()

	for {
		select {
		case buf := <-readChan:
			buffer := string(buf)
			// Some modes completely ignore the RPC call, process them.
			switch self.Mode {
			case TERMINAL, FORWARD:
				self.forwardWSOutput(buffer)
				continue
			case SHELL:
				self.forwardShellOutput(buffer)
				continue
			case LOGCAT:
				self.forwardLogcatOutput(buffer)
				continue
			case FILE:
				if self.Download.Ready {
					self.forwardFileDownloadData(buf)
					continue
				}
			}

			// Only Parse the first message if we are not registered, since
			// if we are in logcat mode, we want to preserve the rest of the
			// data and forward it to the websocket.
			reqs = self.ParseRequests(buffer, !self.registered)
			if err := self.ProcessRequests(reqs); err != nil {
				if _, ok := err.(RegistrationFailedError); ok {
					log.Printf("%s, abort\n", err)
					return
				} else {
					log.Println(err)
				}
			}

			// If self.mode changed, means we just got a registration message and
			// are in a different mode.
			switch self.Mode {
			case TERMINAL, FORWARD:
				// Start a goroutine to forward the WebSocket Input
				go self.forwardWSInput(true)
			case SHELL:
				go self.forwardWSInput(false)
			case LOGCAT:
				// A logcat client does not wait for ACK before sending
				// stream, so we need to forward the remaining content of the buffer
				if self.ReadBuffer != "" {
					self.forwardLogcatOutput(self.ReadBuffer)
					self.ReadBuffer = ""
				}
			}
		case err := <-readErrChan:
			if err == io.EOF {
				if self.Download.Ready {
					self.Download.Data <- nil
					return
				}
				log.Printf("connection dropped: %s\n", self.Sid)
			} else {
				log.Printf("unknown network error for %s: %s\n", self.Sid, err)
			}
			return
		case msg := <-self.Command:
			self.handleOverlordRequest(msg)
		case <-ticker.C:
			if err := self.ScanForTimeoutRequests(); err != nil {
				log.Println(err)
			}

			if self.Mode == AGENT && self.lastPing != 0 &&
				time.Now().Unix()-self.lastPing > PING_RECV_TIMEOUT {
				log.Printf("Client %s timeout\n", self.Mid)
				return
			}
		case s := <-self.stopListen:
			if s {
				return
			}
		}
	}
}

// Request handlers

func (self *ConnServer) handlePingRequest(req *Request) error {
	self.lastPing = time.Now().Unix()
	res := NewResponse(req.Rid, "pong", nil)
	return self.SendResponse(res)
}

func (self *ConnServer) handleRequestTargetSSHPortRequest(req *Request) error {
	// Assume this means that the client's old port is no longer used.
	self.TargetSSHPort = 0
	// Request port number from Overlord.
	port := self.ovl.SuggestTargetSSHPort()
	log.Printf("Offering port %d to client\n", port)
	res := NewResponse(req.Rid, SUCCESS, map[string]interface{}{"port": port})
	return self.SendResponse(res)
}

func (self *ConnServer) handleRegisterTargetSSHPortRequest(req *Request) error {
	type RequestArgs struct {
		Port int `json:"port"`
	}

	var args RequestArgs
	if err := json.Unmarshal(req.Params, &args); err != nil {
		return err
	}
	if args.Port < TARGET_SSH_PORT_START || args.Port > TARGET_SSH_PORT_END {
		return errors.New(
			fmt.Sprintf("handleRegisterTargetSSHPortRequest: Registered port (%d) must be in between %d and %d inclusive",
				args.Port, TARGET_SSH_PORT_START, TARGET_SSH_PORT_END))
	}

	// Save port number.
	log.Printf("Registering port %d for client\n", args.Port)
	self.TargetSSHPort = args.Port
	res := NewResponse(req.Rid, SUCCESS, nil)
	return self.SendResponse(res)
}

func (self *ConnServer) handleRegisterRequest(req *Request) error {
	type RequestArgs struct {
		Sid        string                 `json:"sid"`
		Mid        string                 `json:"mid"`
		Mode       int                    `json:"mode"`
		Format     int                    `json:"format"`
		Properties map[string]interface{} `json:"properties"`
	}

	var args RequestArgs
	if err := json.Unmarshal(req.Params, &args); err != nil {
		return err
	} else {
		if len(args.Mid) == 0 {
			return errors.New("handleRegisterRequest: empty machine ID received")
		}
		if len(args.Sid) == 0 {
			return errors.New("handleRegisterRequest: empty session ID received")
		}
	}

	var err error
	self.Sid = args.Sid
	self.Mid = args.Mid
	self.Mode = args.Mode
	self.logcat.Format = args.Format
	self.SetProperties(args.Properties)

	self.wsConn, err = self.ovl.Register(self)
	if err != nil {
		res := NewResponse(req.Rid, err.Error(), nil)
		self.SendResponse(res)
		return RegistrationFailedError(errors.New("Register: " + err.Error()))
	}

	// Notify client of our Terminal ssesion ID
	if self.Mode == TERMINAL && self.wsConn != nil {
		msg, err := json.Marshal(TerminalControl{"sid", self.Sid})
		if err != nil {
			log.Println("handleRegisterRequest: failed to format message")
		} else {
			self.wsConn.WriteMessage(websocket.TextMessage, msg)
		}
	}

	self.registered = true
	self.lastPing = time.Now().Unix()
	res := NewResponse(req.Rid, SUCCESS, nil)
	return self.SendResponse(res)
}

func (self *ConnServer) handleDownloadRequest(req *Request) error {
	type RequestArgs struct {
		TerminalSid string `json:"terminal_sid"`
		Filename    string `json:"filename"`
		Size        int64  `json:"size"`
	}

	var args RequestArgs
	if err := json.Unmarshal(req.Params, &args); err != nil {
		return err
	}

	self.Download.Ready = true
	self.TerminalSid = args.TerminalSid
	self.Download.Name = args.Filename
	self.Download.Size = args.Size

	self.ovl.RegisterDownloadRequest(self)

	res := NewResponse(req.Rid, SUCCESS, nil)
	return self.SendResponse(res)
}

func (self *ConnServer) handleClearToUploadRequest(req *Request) error {
	self.ovl.RegisterUploadRequest(self)
	return nil
}

func (self *ConnServer) handleRequest(req *Request) error {
	var err error
	switch req.Name {
	case "ping":
		err = self.handlePingRequest(req)
	case "register":
		err = self.handleRegisterRequest(req)
	case "request_to_download":
		err = self.handleDownloadRequest(req)
	case "clear_to_upload":
		err = self.handleClearToUploadRequest(req)
	case "request_target_ssh_port":
		err = self.handleRequestTargetSSHPortRequest(req)
	case "register_target_ssh_port":
		err = self.handleRegisterTargetSSHPortRequest(req)
	}
	return err
}

// Send upgrade request to clients to trigger an upgrade.
func (self *ConnServer) SendUpgradeRequest() error {
	req := NewRequest("upgrade", nil)
	req.SetTimeout(-1)
	return self.SendRequest(req, nil)
}

// Generic handler for remote command
func (self *ConnServer) getHandler(name string) func(res *Response) error {
	return func(res *Response) error {
		if res == nil {
			self.Response <- "command timeout"
			return errors.New(name + ": command timeout")
		}

		if res.Response != SUCCESS {
			self.Response <- res.Response
			return errors.New(name + " failed: " + res.Response)
		}
		self.Response <- ""
		return nil
	}
}

// Spawn a remote terminal connection (a ghost with mode TERMINAL).
// sid is the session ID, which will be used as the session ID of the new ghost.
// ttyDevice is the target terminal device to open. If it's an empty string, a
// pseudo terminal will be open instead.
func (self *ConnServer) SpawnTerminal(sid, ttyDevice string) {
	params := map[string]interface{}{"sid": sid}
	if ttyDevice != "" {
		params["tty_device"] = ttyDevice
	} else {
		params["tty_device"] = nil
	}
	req := NewRequest("terminal", params)
	self.SendRequest(req, self.getHandler("SpawnTerminal"))
}

// Spawn a remote shell command connection (a ghost with mode SHELL).
// sid is the session ID, which will be used as the session ID of the new ghost.
// command is the command to execute.
func (self *ConnServer) SpawnShell(sid string, command string) {
	req := NewRequest("shell", map[string]interface{}{
		"sid": sid, "command": command})
	self.SendRequest(req, self.getHandler("SpawnShell"))
}

// Spawn a remote file command connection (a ghost with mode FILE).
// action is either 'download' or 'upload'.
// sid is used for uploading file, indicatiting which client's working
// directory to upload to.
func (self *ConnServer) SpawnFileServer(sid, terminalSid, action, filename string) {
	if action == "download" {
		req := NewRequest("file_download", map[string]interface{}{
			"sid": sid, "filename": filename})
		self.SendRequest(req, self.getHandler("SpawnFileServer: download"))
	} else if action == "upload" {
		req := NewRequest("file_upload", map[string]interface{}{
			"sid": sid, "terminal_sid": terminalSid, "filename": filename})
		self.SendRequest(req, self.getHandler("SpawnFileServer: upload"))
	} else {
		log.Printf("SpawnFileServer: invalid file action `%s', ignored.\n", action)
	}
}

// Send clear_to_download request to client to start downloading.
func (self *ConnServer) SendClearToDownload() {
	req := NewRequest("clear_to_download", nil)
	req.SetTimeout(-1)
	self.SendRequest(req, nil)
}

// Spawn a forwarder connection (a ghost with mode FORWARD).
// sid is the session ID, which will be used as the session ID of the new ghost.
func (self *ConnServer) SpawnForwarder(sid string, port int) {
	req := NewRequest("forward", map[string]interface{}{
		"sid":  sid,
		"port": port,
	})
	self.SendRequest(req, self.getHandler("SpawnForwarder"))
}
