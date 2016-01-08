package main

import (
	"./whois"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Server struct {
	registry         whois.Registry
	LastConnection   time.Time
	SocketActivation bool
	stopListening    int32
	activeWorkers    sync.WaitGroup
}

func New(dataPath string) *Server {
	registry := whois.Registry{dataPath}
	return &Server{registry, time.Now(), false, 0, sync.WaitGroup{}}
}

func (s *Server) Run(listener *net.TCPListener) {
	atomic.StoreInt32(&s.stopListening, 0)
	s.activeWorkers.Add(1)
	defer s.activeWorkers.Done()
	defer listener.Close()
	for atomic.LoadInt32(&s.stopListening) != 1 {
		if e := listener.SetDeadline(time.Now().Add(time.Second)); e != nil {
			fmt.Fprintf(os.Stderr, "Error setting deadline: %v\n", e)
			continue
		}
		conn, err := listener.AcceptTCP()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				continue
			} else {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

		s.activeWorkers.Add(1)
		s.LastConnection = time.Now()
		go s.handleConn(conn)
	}
}

func (s *Server) Shutdown() {
	atomic.StoreInt32(&s.stopListening, 1)
	s.activeWorkers.Wait()
}

func (s *Server) handleConn(conn *net.TCPConn) {
	defer func() {
		conn.Close()
		s.activeWorkers.Done()
	}()

	s.registry.HandleQuery(conn)
}

type options struct {
	Port          uint
	Address       string
	Registry      string
	SocketTimeout float64
}

func parseFlags() options {
	var o options
	flag.UintVar(&o.Port, "port", 43, "port to listen")
	flag.StringVar(&o.Address, "address", "*", "address to listen")
	flag.StringVar(&o.Registry, "registry", ".", "path to dn42 registry")
	msg := "timeout in seconds before suspending the service when using socket activation"
	flag.Float64Var(&o.SocketTimeout, "timeout", 10, msg)
	flag.Parse()
	if o.Address == "*" {
		o.Address = ""
	}
	return o
}

func Listeners() []*net.TCPListener {
	defer os.Unsetenv("LISTEN_PID")
	defer os.Unsetenv("LISTEN_FDS")

	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() {
		return nil
	}

	nfds, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || nfds == 0 {
		return nil
	}

	listeners := make([]*net.TCPListener, 0)
	for fd := 3; fd < 3+nfds; fd++ {
		syscall.CloseOnExec(fd)
		file := os.NewFile(uintptr(fd), "LISTEN_FD_"+strconv.Itoa(fd))
		if listener, err := net.FileListener(file); err == nil {
			if l, ok := listener.(*net.TCPListener); ok {
				listeners = append(listeners, l)
			}
		}
	}

	return listeners
}

func checkDataPath(registry string) (string, error) {
	dataPath := path.Join(registry, "data")

	if _, err := os.Stat(dataPath); err != nil {
		return "", fmt.Errorf("Cannot access '%s', should be in the registry repository: %s\n",
			dataPath,
			err)
	}
	return dataPath, nil
}

func createServer(opts options) (*Server, error) {
	dataPath, err := checkDataPath(opts.Registry)
	if err != nil {
		return nil, err
	}
	server := New(dataPath)

	if listeners := Listeners(); len(listeners) > 0 {
		fmt.Printf("socket action detected\n")
		server.SocketActivation = true
		for _, listener := range listeners {
			go server.Run(listener)
		}
	} else {
		address := opts.Address + ":" + strconv.Itoa(int(opts.Port))
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return nil, err
		}
		go server.Run(listener.(*net.TCPListener))
	}
	return server, nil
}

func main() {
	opts := parseFlags()
	server, err := createServer(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	signal.Notify(signals, syscall.SIGTERM)
	signal.Notify(signals, syscall.SIGINT)

	if server.SocketActivation {
	Out:
		for {
			select {
			case <-signals:
				break Out
			case <-time.After(time.Second * 3):
				if time.Since(server.LastConnection).Seconds() >= opts.SocketTimeout {
					break Out
				}
			}
		}
	} else {
		<-signals
	}

	fmt.Printf("Shutting socket(s) down (takes up to 1s)\n")
	server.Shutdown()
}
