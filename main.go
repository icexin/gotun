package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"runtime"
	"time"

	"github.com/songgao/water"
)

var (
	localip  = flag.String("l", "10.0.0.1", "local ip")
	peerip   = flag.String("p", "10.0.0.2", "peer ip")
	addr     = flag.String("addr", ":8000", "remote/listen address")
	asserver = flag.Bool("s", false, "run as server")
)

func ifconfig(iface string) error {
	var cmd string
	switch runtime.GOOS {
	case "darwin":
		cmd = fmt.Sprintf("ifconfig %s %s %s up", iface, *localip, *peerip)
	case "linux":
		cmd = fmt.Sprintf("ifconfig %s %s netmask 255.255.255.255 pointopoint %s", iface, *localip, *peerip)
	}

	log.Print(cmd)
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	if err != nil {
		log.Print(string(out))
		return err
	}

	return nil
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

func setupClientIptables() error {

}
func runserver(iface *water.Interface) {
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		handleConn(conn, iface)
		log.Printf("connection from %s closed", conn.RemoteAddr())
	}
}

func runclient(iface *water.Interface) {
	for {
		conn, err := net.Dial("tcp", *addr)
		if err != nil {
			log.Print(err)
			goto sleep
		}

		handleConn(conn, iface)
	sleep:
		time.Sleep(time.Second)
	}
}

func handleConn(conn net.Conn, iface *water.Interface) {
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	go func() {
		defer conn.Close()
		buf := make([]byte, 10240)
		for {
			var hdrlen int16
			err := binary.Read(r, binary.BigEndian, &hdrlen)
			if err != nil {
				return
			}
			if int(hdrlen) > len(buf) {
				log.Printf("bad hdrlen %d", hdrlen)
				return
			}
			_, err = io.ReadFull(r, buf[:hdrlen])
			if err != nil {
				return
			}
			// log.Printf("read conn %d", hdrlen)
			iface.Write(buf[:hdrlen])
		}
	}()
	defer conn.Close()
	buf := make([]byte, 10240)
	for {
		n, err := iface.Read(buf)
		if err != nil {
			return
		}
		// log.Printf("read tun %d", n)

		binary.Write(w, binary.BigEndian, int16(n))
		w.Write(buf[:n])
		err = w.Flush()
		if err != nil {
			return
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
		runserver(iface)
	} else {
		runclient(iface)
	}
}
