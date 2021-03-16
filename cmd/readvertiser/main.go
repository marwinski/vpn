package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/ini.v1"
	"k8s.io/klog/v2"
)

const (
	wireguardDirectory string = "/etc/wireguard"
)

func equals(a, b wgtypes.Key) bool {
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func getPeer(wireguardDevice string, peerKey wgtypes.Key) (*wgtypes.Peer, error) {

	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("Unable to initialize wireguard client: %v", err)
	}
	dev, err := client.Device(wireguardDevice)
	if err != nil {
		return nil, fmt.Errorf("Unable to get wireguard device: %v", err)
	}
	for _, p := range dev.Peers {
		if equals(p.PublicKey, peerKey) {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("Peer with provided peer public key not found.")
}

// read IP address from wireguard device
func readIP(wireguardDevice string, peerKey wgtypes.Key) (net.IP, error) {

	peer, err := getPeer(wireguardDevice, peerKey)
	if err != nil {
		return nil, err
	} else {
		return peer.Endpoint.IP, nil
	}
}

func updateIP(wireguardDevice string, peerKey wgtypes.Key, newIP net.IP) error {

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("Unable to initialize wireguard client: %v", err)
	}
	dev, err := client.Device(wireguardDevice)
	if err != nil {
		return fmt.Errorf("Unable to get wireguard device: %v", err)
	}

	config := wgtypes.Config{
		PrivateKey:   &dev.PrivateKey,
		FirewallMark: &dev.FirewallMark,
		ReplacePeers: false,
		ListenPort:   &dev.ListenPort,
	}
	var peerConfigs []wgtypes.PeerConfig

	for _, v := range dev.Peers {

		pc := wgtypes.PeerConfig{
			PublicKey:                   v.PublicKey,
			Remove:                      false,
			UpdateOnly:                  true,
			PresharedKey:                &v.PresharedKey,
			Endpoint:                    v.Endpoint,
			PersistentKeepaliveInterval: &v.PersistentKeepaliveInterval,
			AllowedIPs:                  v.AllowedIPs,
			ReplaceAllowedIPs:           false,
		}
		if equals(peerKey, v.PublicKey) {
			pc.Endpoint.IP = newIP

		}
		peerConfigs = append(peerConfigs, pc)
	}
	config.Peers = peerConfigs
	return client.ConfigureDevice(dev.Name, config)
}

func isInList(list []net.IP, ip net.IP) bool {
	for _, ipl := range list {
		if ip.Equal(ipl) {
			return true
		}
	}
	return false
}

func parseEndpoint(hostPort string) *string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		klog.Errorf("Error reading endpoint %s: %v", hostPort, err)
		os.Exit(1)
	}
	return &host
}

func main() {

	klog.InitFlags(nil)
	wireguardDevice := flag.String("wireguard-device", "", "wireguard device")
	refreshTime := flag.Int("refresh-time", 60, "time in seconds between IP address checks")
	flag.Parse()

	if *wireguardDevice == "" {
		klog.Errorf("Must specify --wireguard-device")
		os.Exit(1)
	}

	wireguardConfig := wireguardDirectory + "/" + *wireguardDevice + ".conf"
	cfg, err := ini.LoadSources(ini.LoadOptions{
		AllowNonUniqueSections: true,
	}, wireguardConfig)
	if err != nil {
		klog.Errorf("Fail to read wireguard config file %s: %v", wireguardConfig, err)
		os.Exit(1)
	}
	secs := cfg.Sections()
	var peerSection *ini.Section
	for _, v := range secs {
		if v.Name() == "Peer" {
			peerSection = v
		}
	}
	if peerSection == nil {
		klog.Errorf("No peer section in wireguard configuration.")
		os.Exit(1)
	}

	pkey, err := peerSection.GetKey("PublicKey")
	if err != nil {
		klog.Errorf("No public Key in peer section: %v", err)
		os.Exit(1)
	}

	endpointKey, err := peerSection.GetKey("Endpoint")
	if err != nil {
		klog.Errorf("No endpoint in peer section: %v", err)
		os.Exit(1)
	}
	dnsNameOrIP := parseEndpoint(endpointKey.Value())

	ipCand := net.ParseIP(*dnsNameOrIP)
	if ipCand != nil {
		klog.Infof("Configured endpoint %s is an IP address. No need to do anything. Sleeping until pod is terminated...\n", *dnsNameOrIP)
		<-make(chan int)
	}

	dnsName := dnsNameOrIP
	pk, err := base64.StdEncoding.DecodeString(pkey.Value())
	if err != nil || len(pk) != wgtypes.KeyLen {
		klog.Errorf("Unable to decode peer string or key length not 32 bytes: %v", err)
		os.Exit(1)
	}
	var peerKey wgtypes.Key
	copy(peerKey[:], pk)

	for {
		time.Sleep(time.Duration(*refreshTime) * time.Second)
		ips, err := net.LookupIP(*dnsName)
		if err != nil {
			klog.Errorf("Unable to look up dns name %s: %v", *dnsName, err)
			continue
		}
		configuredIP, err := readIP(*wireguardDevice, peerKey)
		if err != nil {
			klog.Errorf("Unable to obtain ip address from wireguard device %s, peer %s: %v, wire", *wireguardDevice, pkey.Value(), err)
			continue
		}
		if isInList(ips, configuredIP) {
			klog.Infof("Correct IP %s configured on wireguard device %s for peer %s.", configuredIP.String(), *wireguardDevice, pkey.Value())
			continue
		}
		klog.Infof("Updating IP address on wireguard interface. Configured IP is %s, correct one is %s", configuredIP.String(), ips[0].String())

		err = updateIP(*wireguardDevice, peerKey, ips[0])
		if err != nil {
			klog.Errorf("Unable to update endpoint IP address to %s for peer %s: %v", ips[0], pkey.Value(), err)
		}
	}
}
