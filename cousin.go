package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"encoding/binary"
	"reflect"

	"github.com/miekg/pcap"
)


var (
	device = flag.String("i", "", "The interface to listen on")
	expr = flag.String("e", "src port 443", "Triggering libpcap expression")
	nentries = flag.Int("n", 1, "Number of frames to capture")
)

type Cousinable struct {
	MAC	net.HardwareAddr
	IP	net.IP
	GatewayMAC	net.HardwareAddr
}

func main() {
	flag.Parse()
	if *device == "" {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatalf("Unable to find any interfaces: %v", err)
		}
		if len(devs) == 0 {
			log.Fatalf("No interfaces found")
		}
		*device = devs[0].Name
	}
	log.Printf("Using device %v", *device)

	h, err := pcap.OpenLive(*device, 65535, true, 500)
	if h == nil {
		log.Fatalf("unable to open interface: %v", err)
	}

	defer h.Close()

	var cousinables []Cousinable

	err = h.SetFilter(*expr)
	if err != nil {
		log.Fatalf("Unable to set filter: %v", err)
	}

	for pkt, r := h.NextEx(); r >= 0; pkt, r = h.NextEx() {
		if r == 0 {
			continue
		}
		pkt.Decode()
		srcMAC := Uint64toHardwareAddr(pkt.SrcMac)
		dstMAC := Uint64toHardwareAddr(pkt.DestMac)
		fmt.Printf("Packet data %x\n", pkt.Data)
		log.Printf("Headers: %v", pkt.Headers)
		//srcIP := net.IP(pkt.Headers[0].(*pcap.Iphdr).SrcIp)
		dstIP := net.IP(pkt.Headers[0].(*pcap.Iphdr).DestIp)
		cousinable := Cousinable{dstMAC, dstIP, srcMAC}
		//log.Printf("%v -> %v [%v -> %v]", srcMAC, dstMAC, srcIP, dstIP)

		found := false
		for _, v := range cousinables {
			if reflect.DeepEqual(v.MAC, cousinable.MAC) {
				found = true
				break
			}
		}
		if !found {
			cousinables = append(cousinables, cousinable)
			log.Printf("A cousinable: %v", cousinable)
}
		if len(cousinables) >= *nentries {
			break;
		}
	}
	fmt.Printf("COUSIN_IF=%v COUSIN_MAC=%v COUSIN_IP=%v GATEWAY_MAC=%v\n",
		   *device, cousinables[0].MAC, cousinables[0].IP, cousinables[0].GatewayMAC)


}


func Uint64toHardwareAddr(u uint64) net.HardwareAddr {
	MAC := make(net.HardwareAddr, 8)
	binary.BigEndian.PutUint64(MAC, u)
	MAC = MAC[2:]
	return MAC
}
