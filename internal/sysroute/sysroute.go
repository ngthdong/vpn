package sysroute

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

type DefaultRoute struct {
	Route netlink.Route
}

func Setup(
	tunName string,
	serverIP net.IP,
) (*DefaultRoute, error) {
	dr, err := GetDefaultRoute()
	if err != nil {
		return nil, err
	}

	if err := AddHostRoute(serverIP, dr); err != nil {
		return nil, err
	}

	if err := ReplaceDefaultRoute(tunName, dr); err != nil {
		return nil, err
	}

	return dr, nil
}

// return the current IPv4 default route.
// Example: default via 192.168.1.1 dev wlan0
func GetDefaultRoute() (*DefaultRoute, error) {
	_, dst, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return nil, fmt.Errorf("parse default route: %w", err)
	}

	filter := &netlink.Route{
		Dst: dst,
	}

	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V4,
		filter,
		netlink.RT_FILTER_DST,
	)
	if err != nil {
		return nil, fmt.Errorf("list default route: %w", err)
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf("default route not found")
	}

	return &DefaultRoute{
		Route: routes[0],
	}, nil
}

func AddHostRoute(host net.IP, defaultRoute *DefaultRoute) error {
	_, dst, err := net.ParseCIDR(host.String() + "/32")
	if err != nil {
		return fmt.Errorf("parse host route: %w", err)
	}

	route := netlink.Route{
		Dst:       dst,
		Gw:        defaultRoute.Route.Gw,
		LinkIndex: defaultRoute.Route.LinkIndex,
	}

	if err := netlink.RouteReplace(&route); err != nil {
		return fmt.Errorf("replace host route: %w", err)
	}

	return nil
}

func ReplaceDefaultRoute(tunName string, defaultRoute *DefaultRoute) error {
	link, err := netlink.LinkByName(tunName)
    if err != nil {
        return fmt.Errorf("lookup link %q: %w", tunName, err)
    }

    if err := netlink.RouteDel(&defaultRoute.Route); err != nil {
        return fmt.Errorf("delete default route: %w", err)
    }

    _, dst, _ := net.ParseCIDR("0.0.0.0/0")

    return netlink.RouteReplace(&netlink.Route{
        Dst:       dst,
        LinkIndex: link.Attrs().Index,
    })
}

func DeleteHostRoute(
	host net.IP,
	defaultRoute *DefaultRoute,
) error {
	_, dst, err := net.ParseCIDR(host.String() + "/32")
	if err != nil {
		return fmt.Errorf("parse host route: %w", err)
	}

	route := netlink.Route{
		Dst:       dst,
		Gw:        defaultRoute.Route.Gw,
		LinkIndex: defaultRoute.Route.LinkIndex,
	}

	if err := netlink.RouteDel(&route); err != nil {
		return fmt.Errorf("delete host route: %w", err)
	}

	return nil
}

func RestoreDefaultRoute(tunName string, defaultRoute *DefaultRoute) error {
	link, err := netlink.LinkByName(tunName)
	if err != nil {
		return fmt.Errorf("lookup link %q: %w", tunName, err)
	}

	_, defaultNet, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return fmt.Errorf("parse default route: %w", err)
	}

	tunRoute := netlink.Route{
		Dst:       defaultNet,
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
	}

	// Remove default via TUN.
	if err := netlink.RouteDel(&tunRoute); err != nil {
		return fmt.Errorf("delete tun default route: %w", err)
	}

	// Restore original default route.
	if err := netlink.RouteAdd(&defaultRoute.Route); err != nil {
		return fmt.Errorf("restore default route: %w", err)
	}

	return nil
}
