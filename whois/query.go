package whois

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

type Registry struct {
	DataPath string
}

type Type struct {
	Name    string
	Pattern *regexp.Regexp
	Kind    int
}

type Object map[int]interface{}

const (
	UPPER = iota
	LOWER
	ROUTE
	ROUTE6
)

type Query struct {
	Objects []Object
	Flags   *Flags
}

var whoisTypes = []Type{
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

func (r *Registry) handleObject(conn *net.TCPConn, object Object) bool {
	found := false
	for _, t := range whoisTypes {
		if t.Kind == ROUTE || t.Kind == ROUTE6 {
			if object[t.Kind] != nil {
				found = found || r.printNet(conn, t.Name, object[t.Kind].(net.IP))
			}
		} else {
			arg := object[t.Kind].(string)
			if t.Pattern.MatchString(arg) {
				r.printObject(conn, t.Name, arg)
				found = true
			}
		}
	}
	return found
}

func (r *Registry) HandleQuery(conn *net.TCPConn) {
	fmt.Fprint(conn, "% This is the dn42 whois query service.\n\n")

	query := parseQuery(conn)
	if query == nil {
		return
	}

	flags := query.Flags
	if flags.ServerInfo != "" {
		r.printServerInfo(conn, flags.ServerInfo)
		return
	}
	found := false
	for _, obj := range query.Objects {
		if r.handleObject(conn, obj) {
			found = true
		}
	}

	if !found {
		fmt.Fprint(conn, "% 404\n")
	}
	fmt.Fprint(conn, "\n")
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

func parseObject(arg string) Object {
	obj := path.Base(arg)
	object := Object{
		UPPER: strings.ToUpper(obj),
		LOWER: strings.ToLower(obj),
	}

	ip := net.ParseIP(obj)
	if ip == nil {
		ip, _, _ = net.ParseCIDR(arg)
	}
	if ip != nil {
		if ip.To4() == nil {
			object[ROUTE6] = ip
		} else {
			object[ROUTE] = ip.To4()
		}
	}
	return object
}

func parseQuery(conn *net.TCPConn) *Query {
	r := bufio.NewReader(conn)
	req, e := r.ReadString('\n')
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", e)
		return nil
	}
	flags, flagSet, err := parseFlags(req)
	if err != nil {
		flagSet.SetOutput(conn)
		if err != flag.ErrHelp {
			fmt.Fprintf(conn, "%s", err)
		}
		flagSet.PrintDefaults()
		return nil
	}

	query := Query{}
	query.Flags = flags
	query.Objects = make([]Object, len(flags.Args))
	for i, arg := range flags.Args {
		query.Objects[i] = parseObject(strings.TrimSpace(arg))
	}
	fmt.Fprintf(os.Stdout, "[%s] %s\n", conn.RemoteAddr(), req)
	return &query
}

func (r *Registry) printServerInfo(conn *net.TCPConn, what string) {
	switch what {
	case "version":
		fmt.Fprintf(conn, "%% whois42d v%d\n", VERSION)
	case "sources":
		fmt.Fprintf(conn, "DN42:3:N:0-0\n")
	case "types":
		for _, t := range whoisTypes {
			fmt.Fprintf(conn, "%s\n", t.Name)
		}
	default:
		fmt.Fprintf(conn, "% unknown option %s\n", what)
	}
}

func (r *Registry) printNet(conn *net.TCPConn, name string, ip net.IP) bool {
	routePath := path.Join(r.DataPath, name)
	cidrs, err := readCidrs(routePath)
	if err != nil {
		fmt.Printf("Error reading cidr from '%s'\n", routePath)
	}

	found := false
	for _, c := range cidrs {
		if c.Contains(ip) {
			obj := strings.Replace(c.String(), "/", "_", -1)
			r.printObject(conn, name, obj)
			found = true
		}
	}
	return found
}

func (r *Registry) printObject(conn *net.TCPConn, objType string, obj string) {
	file := path.Join(r.DataPath, objType, obj)

	f, err := os.Open(file)
	defer f.Close()
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return
	}
	fmt.Fprintf(conn, "%% Information related to '%s':\n", file[len(r.DataPath)+1:])
	conn.ReadFrom(f)
	fmt.Fprint(conn, "\n")
}
