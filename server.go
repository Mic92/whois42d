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
	"strings"
	"syscall"
)

type Server struct {
	DataPath string
}

func (s Server) Run(listener *net.TCPListener) {
	for {
		conn, e := listener.AcceptTCP()
		if e != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", e)
			continue
		}

		go s.handleConn(conn)
	}
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

func (s Server) handleConn(conn *net.TCPConn) {
	defer conn.Close()
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

func (s Server) printNet(conn *net.TCPConn, name string, ip net.IP) bool {
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

func (s Server) printObject(conn *net.TCPConn, objType string, obj string) {
	f, err := os.Open(path.Join(s.DataPath, objType, obj))
	defer f.Close()
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	conn.ReadFrom(f)
}

type options struct {
	Port     uint
	Address  string
	Registry string
	User     string
	Group    string
}

func parseFlags() options {
	var o options
	flag.UintVar(&o.Port, "port", 43, "port to listen")
	flag.StringVar(&o.Address, "address", "*", "address to listen")
	flag.StringVar(&o.Registry, "registry", ".", "path to dn42 registry")
	flag.Parse()
	if o.Address == "*" {
		o.Address = ""
	}
	return o
}

func main() {
	opts := parseFlags()
	registryPath := path.Join(opts.Registry, "data")

	if _, err := os.Stat(registryPath); err != nil {
		fmt.Fprintf(os.Stderr,
			"Cannot access '%s', should be in the registry repository: %s\n",
			registryPath,
			err)
		os.Exit(1)
	}

	address := opts.Address + ":" + fmt.Sprint(opts.Port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	server := Server{registryPath}
	go server.Run(listener.(*net.TCPListener))

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)
	signal.Notify(c, syscall.SIGINT)

	for {
		select {
		case <-c:
			fmt.Printf("Shutting socket down\n")
			listener.Close()
			os.Exit(0)
		}
	}
}
