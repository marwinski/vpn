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
	"k8s.io/klog/v2"
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
		ReplacePeers: true,
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

func main() {
	klog.InitFlags(nil)
	wireguardDevice := flag.String("wireguardDevice", "", "wireguard device")
	peerPublicKey := flag.String("peer", "", "peer public key")
	dnsName := flag.String("dns-name", "", "dns name")
	refreshTime := flag.Int("refresh-time", 60, "time in seconds between IP address checks")
	flag.Parse()

	pk, err := base64.StdEncoding.DecodeString(*peerPublicKey)
	if err != nil || len(pk) != wgtypes.KeyLen {
		fmt.Errorf("Unable to decode peer string or key length not %d bytes: %v", len(pk), err)
		os.Exit(1)
	}
	var peerKey wgtypes.Key
	copy(peerKey[:], pk)

	for {
		time.Sleep(time.Duration(*refreshTime) * time.Second)
		ips, err := net.LookupIP(*dnsName)
		if err != nil {
			klog.Errorf("Unable to look up dns name %s: %v", dnsName, err)
			continue
		}
		configuredIP, err := readIP(*wireguardDevice, peerKey)
		if err != nil {
			klog.Errorf("Unable to obtain ip address from wireguard interface %s, peer %s: %v, wire")
			continue
		}
		if isInList(ips, configuredIP) {
			klog.Infof("Correct IP %s configured on wireguard interface %s for peer %s.", configuredIP.String(), *wireguardDevice, *peerPublicKey)
			continue
		}
		klog.Infof("Updating IP address on wireguard interface.")

		err = updateIP(*wireguardDevice, peerKey, ips[0])
		if err != nil {
			klog.Errorf("Unable to update endpoint IP address to %s for peer %s: %v", ips[0], *peerPublicKey, err)
		}

	}
}
