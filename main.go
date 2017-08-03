package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"sync/atomic"

	"github.com/coreos/go-iptables/iptables"
	"github.com/songgao/water"
)

var (
	localip  = flag.String("l", "10.0.0.1", "local ip")
	peerip   = flag.String("p", "10.0.0.2", "peer ip")
	addr     = flag.String("addr", ":8000", "remote/listen address")
	asserver = flag.Bool("s", false, "run as server")
)

func system(s string) error {
	out, err := exec.Command("bash", "-c", s).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s:%s", err, out)
	}

	return nil
}

func ifconfig(iface string) error {
	var cmd string
	switch runtime.GOOS {
	case "darwin":
		cmd = fmt.Sprintf("ifconfig %s %s %s up", iface, *localip, *peerip)
	case "linux":
		cmd = fmt.Sprintf("ifconfig %s %s netmask 255.255.255.255 pointopoint %s", iface, *localip, *peerip)
	}

	log.Print(cmd)
	return system(cmd)
}

func setupIface() (*water.Interface, error) {
	iface, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return nil, err
	}

	log.Print(iface.Name())

	err = ifconfig(iface.Name())
	if err != nil {
		return nil, err
	}

	return iface, nil
}

func setupIptables(ifaceName string) error {
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
	err = t.AppendUnique("nat", "GOTUN-MARK", "-i", ifaceName, "-j", "MARK", "--set-mark", "12321")
	if err != nil {
		return err
	}

	err = t.AppendUnique("nat", "GOTUN-NAT", "-m", "mark", "--mark", "12321", "!", "-d", *localip, "-j", "MASQUERADE")
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

func runserver(iface *water.Interface) {
	listenaddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", listenaddr)
	if err != nil {
		log.Fatal(err)
	}
	handleConn(conn, iface, nil)
}

func runclient(iface *water.Interface) {
	remoteaddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, remoteaddr)
	if err != nil {
		log.Fatal(err)
	}
	handleConn(conn, iface, remoteaddr)
}

func handleConn(conn *net.UDPConn, iface *water.Interface, remoteaddr net.Addr) {
	var isclient bool
	var remote atomic.Value
	if remoteaddr != nil {
		isclient = true
	} else {
		remoteaddr = &net.UDPAddr{}
	}
	remote.Store(remoteaddr)

	go loopReadIface(iface, conn, &remote, isclient)

	buf := make([]byte, 1600)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Print(err)
			continue
		}
		log.Printf("conn read %d", n)

		if addr.String() != remoteaddr.String() {
			log.Printf("remote changed %s -> %s", remoteaddr, addr)
			remoteaddr = addr
			remote.Store(addr)
		}
		_, err = iface.Write(buf[:n])
		if err != nil {
			log.Panic(err)
		}
	}
}

func loopReadIface(iface *water.Interface, conn *net.UDPConn, remote *atomic.Value, isclient bool) {
	buf := make([]byte, 1600)
	for {
		n, err := iface.Read(buf)
		if err != nil {
			log.Panic(err)
		}
		log.Printf("iface read %d", n)

		s := buf[:n]

		if isclient {
			_, err = conn.Write(s)
			if err != nil {
				log.Print(err)
			}
		} else {
			addr := remote.Load()
			if addr == nil {
				continue
			}

			_, err = conn.WriteTo(s, addr.(net.Addr))
			if err != nil {
				log.Print(err)
			}
		}
	}
}

func main() {
	flag.Parse()

	iface, err := setupIface()
	if err != nil {
		log.Fatal(err)
	}

	if *asserver {
		err = setupIptables(iface.Name())
		if err != nil {
			log.Fatal(err)
		}
		runserver(iface)
	} else {
		runclient(iface)
	}
}
