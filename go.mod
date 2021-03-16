module https: //github.com/marwinski/vpn

go 1.15

require (
	github.com/smartystreets/goconvey v1.6.4 // indirect
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20200609130330-bd2cb7843e1b
	gopkg.in/ini.v1 v1.62.0
	k8s.io/klog/v2 v2.2.0
)

//replace golang.zx2c4.com/wireguard/wgctrl => github.com/mandelsoft/wgctrl-go v0.0.0-20210208121059-d9ab8e5d81ee
