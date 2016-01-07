package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Server struct {
	DataPath         string
	LastConnection   time.Time
	SocketActivation bool
	stopListening    int32
	activeWorkers    sync.WaitGroup
}

func New(dataPath string) *Server {
	return &Server{dataPath, time.Now(), false, 0, sync.WaitGroup{}}
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

func readCidrs(path string) ([]net.IPNet, error) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}
	cidrs := []net.IPNet{}
	for _, f := range files {
		name := strings.Replace(f.Name(), "_", "/", -1)
		_, cidr, err := net.ParseCIDR(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip invalid net '%s'", f.Name())
			continue
		}
		i := sort.Search(len(cidrs), func(i int) bool {
			c := cidrs[i]
			return bytes.Compare(c.Mask, cidr.Mask) >= 0
		})

		if i < len(cidrs) {
			cidrs = append(cidrs[:i], append([]net.IPNet{*cidr}, cidrs[i:]...)...)
		} else {
			cidrs = append(cidrs, *cidr)
		}
	}

	return cidrs, nil
}

type WhoisType struct {
	Name    string
	Pattern *regexp.Regexp
	Kind    int
}

const (
	UPPER = iota
	LOWER
	ROUTE
	ROUTE6
)

var whoisTypes = []WhoisType{
	{"aut-num", regexp.MustCompile(`^AS([0123456789]+)$`), UPPER},
	{"dns", regexp.MustCompile(`.dn42$`), LOWER},
	{"person", regexp.MustCompile(`-DN42$`), UPPER},
	{"mntner", regexp.MustCompile(`-MNT$`), UPPER},
	{"schema", regexp.MustCompile(`-SCHEMA$`), UPPER},
	{"organisation", regexp.MustCompile(`ORG-`), UPPER},
	{"tinc-keyset", regexp.MustCompile(`^SET-.+-TINC$`), UPPER},
	{"tinc-key", regexp.MustCompile(`-TINC$`), UPPER},
	{"as-set", regexp.MustCompile(`^AS`), UPPER},
	{"route-set", regexp.MustCompile(`^RS-`), UPPER},
	{"inetnum", nil, ROUTE},
	{"inet6num", nil, ROUTE6},
	{"route", nil, ROUTE},
	{"route6", nil, ROUTE6},
	{"as-block", regexp.MustCompile(`\d+_\d+`), UPPER},
}

func parseQuery(conn *net.TCPConn) map[int]interface{} {
	r := bufio.NewReader(conn)
	req, e := r.ReadString('\n')
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", e)
		return nil
	}
	obj := path.Base(strings.TrimSpace(req))
	queryArgs := map[int]interface{}{
		UPPER: strings.ToUpper(obj),
		LOWER: strings.ToLower(obj),
	}
	ip := net.ParseIP(obj)
	if ip == nil {
		ip, _, _ = net.ParseCIDR(strings.TrimSpace(req))
	}
	if ip != nil {
		if ip.To4() == nil {
			queryArgs[ROUTE6] = ip
		} else {
			queryArgs[ROUTE] = ip.To4()
		}
	}
	fmt.Fprintf(os.Stdout, "[%s] %s\n", conn.RemoteAddr(), obj)
	return queryArgs
}

func (s *Server) handleConn(conn *net.TCPConn) {
	defer func() {
		conn.Close()
		s.activeWorkers.Done()
	}()

	queryArgs := parseQuery(conn)
	if queryArgs == nil {
		return
	}

	found := false
	for _, t := range whoisTypes {
		if t.Kind == ROUTE || t.Kind == ROUTE6 {
			if queryArgs[t.Kind] != nil {
				found = found || s.printNet(conn, t.Name, queryArgs[t.Kind].(net.IP))
			}
		} else {
			arg := queryArgs[t.Kind].(string)
			if t.Pattern.MatchString(arg) {
				s.printObject(conn, t.Name, arg)
				found = true
			}
		}
	}

	if !found {
		fmt.Fprint(conn, "% 404")
	}
}

func (s *Server) printNet(conn *net.TCPConn, name string, ip net.IP) bool {
	routePath := path.Join(s.DataPath, name)
	cidrs, err := readCidrs(routePath)
	if err != nil {
		fmt.Printf("Error reading cidr from '%s'\n", routePath)
	}

	found := false
	for _, c := range cidrs {
		if c.Contains(ip) {
			obj := strings.Replace(c.String(), "/", "_", -1)
			s.printObject(conn, name, obj)
			found = true
		}
	}
	return found
}

func (s *Server) printObject(conn *net.TCPConn, objType string, obj string) {
	f, err := os.Open(path.Join(s.DataPath, objType, obj))
	defer f.Close()
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	conn.ReadFrom(f)
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
