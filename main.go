package main

import (
	"bufio"
	"crypto/md5"
	"crypto/rc4"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/coreos/go-iptables/iptables"
	"github.com/songgao/water"
)

var (
	cip      = flag.String("cip", "10.0.0.1", "client tun ip")
	sip      = flag.String("sip", "10.0.0.2", "server tun ip")
	addr     = flag.String("addr", ":8000", "remote/listen address")
	asserver = flag.Bool("s", false, "run as server")
	iplist   = flag.String("iplist", "iplist.txt", "a file contains ip list to forward")
	skey     = flag.String("k", "123456", "secret key")
)

func system(s string) error {
	out, err := exec.Command("bash", "-c", s).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s:%s", err, out)
	}

	return nil
}

func ifconfig(iface string) error {
	localip := *cip
	remoteip := *sip
	if *asserver {
		localip = *sip
		remoteip = *cip
	}

	var cmd string
	switch runtime.GOOS {
	case "darwin":
		cmd = fmt.Sprintf("ifconfig %s %s %s up", iface, localip, remoteip)
	case "linux":
		cmd = fmt.Sprintf("ifconfig %s %s netmask 255.255.255.255 pointopoint %s", iface, localip, remoteip)
	}

	log.Print(cmd)
	return system(cmd)
}

type Cipher struct {
	secret []byte
}

func NewCipher(key string) *Cipher {
	sum := md5.Sum([]byte(key))
	return &Cipher{
		secret: sum[:],
	}
}

func (c *Cipher) initCipher() *rc4.Cipher {
	cipher, err := rc4.NewCipher(c.secret)
	if err != nil {
		panic(err)
	}
	return cipher
}

func (c *Cipher) Encode(b []byte) {
	cipher := c.initCipher()
	cipher.XORKeyStream(b, b)
}

func (c *Cipher) Decode(b []byte) {
	cipher := c.initCipher()
	cipher.XORKeyStream(b, b)
}

type Tun struct {
	iface  *water.Interface
	conn   *net.UDPConn
	remote *net.UDPAddr
	cipher *Cipher
}

func (tun *Tun) setupIptables() error {
	if runtime.GOOS != "linux" {
		return nil
	}

	err := system("echo 1 > /proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return err
	}

	t, err := iptables.New()
	if err != nil {
		return err
	}

	t.NewChain("nat", "GOTUN-NAT")
	t.NewChain("nat", "GOTUN-MARK")

	t.ClearChain("nat", "GOTUN-NAT")
	t.ClearChain("nat", "GOTUN-MARK")

	// mark packets from iface
	err = t.AppendUnique("nat", "GOTUN-MARK", "-i", tun.iface.Name(), "-j", "MARK", "--set-mark", "12321")
	if err != nil {
		return err
	}

	localip := *cip
	if *asserver {
		localip = *sip
	}
	err = t.AppendUnique("nat", "GOTUN-NAT", "-m", "mark", "--mark", "12321", "!", "-d", localip, "-j", "MASQUERADE")
	if err != nil {
		return err
	}

	err = t.AppendUnique("nat", "PREROUTING", "-j", "GOTUN-MARK")
	if err != nil {
		return err
	}
	err = t.AppendUnique("nat", "POSTROUTING", "-j", "GOTUN-NAT")
	if err != nil {
		return err
	}
	return nil
}

func (t *Tun) addRoute(ip string) error {
	var cmd string
	switch runtime.GOOS {
	case "darwin":
		cmd = fmt.Sprintf("route add -net %s -interface %s", ip, t.iface.Name())
	}

	return system(cmd)
}

func (t *Tun) setupRoute() error {
	if *iplist == "" {
		return nil
	}
	f, err := os.Open(*iplist)
	if err != nil {
		return err
	}
	defer f.Close()

	r := bufio.NewScanner(f)
	for r.Scan() {
		ip := strings.TrimSpace(r.Text())
		err = t.addRoute(ip)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *Tun) setupIface() error {
	var err error
	t.iface, err = water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return err
	}

	log.Print(t.iface.Name())

	err = ifconfig(t.iface.Name())
	if err != nil {
		return err
	}

	return nil
}

func (t *Tun) setupCipher() {
	t.cipher = NewCipher(*skey)
}

func (t *Tun) runserver() {
	listenaddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	t.conn, err = net.ListenUDP("udp", listenaddr)
	if err != nil {
		log.Fatal(err)
	}
	t.remote = &net.UDPAddr{}
	t.handleConn()
}

func (t *Tun) runclient() {
	var err error
	t.remote, err = net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	t.conn, err = net.DialUDP("udp", nil, t.remote)
	if err != nil {
		log.Fatal(err)
	}
	t.handleConn()
}

func (t *Tun) handleConn() {
	var remote atomic.Value
	var remoteaddr net.Addr = t.remote
	remote.Store(remoteaddr)
	go t.loopReadIface(&remote)

	buf := make([]byte, 1600)
	for {
		n, addr, err := t.conn.ReadFrom(buf)
		if err != nil {
			log.Print(err)
			continue
		}
		content := buf[:n]
		t.setupCipher()
		t.cipher.Decode(content)
		log.Printf("conn read %d", n)

		if addr.String() != remoteaddr.String() {
			log.Printf("remote changed %s -> %s", remoteaddr, addr)
			remoteaddr = addr
			remote.Store(addr)
		}
		_, err = t.iface.Write(content)
		if err != nil {
			log.Print(err)
		}
	}
}

func (t *Tun) loopReadIface(remote *atomic.Value) {
	buf := make([]byte, 1600)
	for {
		n, err := t.iface.Read(buf)
		if err != nil {
			log.Panic(err)
		}
		log.Printf("iface read %d", n)

		content := buf[:n]
		t.setupCipher()
		t.cipher.Encode(content)

		if !*asserver {
			_, err = t.conn.Write(content)
			if err != nil {
				log.Print(err)
			}
		} else {
			addr := remote.Load()
			if addr == nil {
				continue
			}

			_, err = t.conn.WriteTo(content, addr.(net.Addr))
			if err != nil {
				log.Print(err)
			}
		}
	}
}

func main() {
	flag.Parse()

	var t Tun
	err := t.setupIface()
	if err != nil {
		log.Fatal(err)
	}

	t.setupCipher()

	if *asserver {
		err = t.setupIptables()
		if err != nil {
			log.Fatal(err)
		}
		t.runserver()
	} else {
		err = t.setupRoute()
		if err != nil {
			log.Fatal(err)
		}
		t.runclient()
	}
}
