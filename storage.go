package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"time"

	etcd "github.com/coreos/etcd/clientv3"
	etcdutil "github.com/coreos/etcd/clientv3/clientv3util"
	etcdpb "github.com/coreos/etcd/etcdserver/etcdserverpb"
	"github.com/golang/glog"
	dhcp "github.com/krolaw/dhcp4"
	"github.com/pkg/errors"
)

var (
	monitorInterval = flag.Duration("dhcp.monitor-interval", time.Minute*5, "period to resurrect ips from expired leases at")
)

func (h *DHCPHandler) bootstrapLeasableRange(ctx context.Context) error {
	kvc := etcd.NewKV(h.client)
	for ip := h.start; !ip.Equal(h.end); ip = dhcp.IPAdd(ip, 1) {
		freeIPKey := h.prefix + "ips::free::" + ip.String()
		leasedIPKey := h.prefix + "ips::leased::" + ip.String()
		reservedIPKey := h.prefix + "ips::reserved::" + ip.String()
		res, err := kvc.Txn(ctx).If(
			etcdutil.KeyMissing(freeIPKey),
			etcdutil.KeyMissing(leasedIPKey),
			etcdutil.KeyMissing(reservedIPKey),
		).Then(
			etcd.OpPut(freeIPKey, ip.String()),
		).Commit()
		if err != nil {
			return errors.Wrap(err, "could not move ip to free state")
		}
		if res.Succeeded {
			glog.Infof("established %v as free", ip)
		}
	}
	return nil
}

func (h *DHCPHandler) monitorLeases(ctx context.Context) error {
	t := time.NewTicker(*monitorInterval)
	defer t.Stop()
	for {
		err := h.resurrectLeases(ctx)
		if err != nil {
			glog.Errorf("could not resurrect leases: %v", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (h *DHCPHandler) resurrectLeases(ctx context.Context) error {
	kvc := etcd.NewKV(h.client)

	leasedIPPrefix := h.prefix + "ips::leased::"
	leased, err := getKeyExistenceMap(ctx, &kvc, leasedIPPrefix)
	if err != nil {
		return errors.Wrap(err, "could not list lease ips")
	}

	freeIPPrefix := h.prefix + "ips::free::"
	free, err := getKeyExistenceMap(ctx, &kvc, freeIPPrefix)
	if err != nil {
		return errors.Wrap(err, "could not list lease ips")
	}

	reservedIPPrefix := h.prefix + "ips::reserved::"
	reserved, err := getKeyExistenceMap(ctx, &kvc, reservedIPPrefix)
	if err != nil {
		return errors.Wrap(err, "could not list lease ips")
	}

	for ip := h.start; !ip.Equal(h.end); ip = dhcp.IPAdd(ip, 1) {
		if _, ok := (*free)[ip.String()]; ok {
			continue
		}
		if _, ok := (*leased)[ip.String()]; ok {
			continue
		}
		if _, ok := (*reserved)[ip.String()]; ok {
			continue
		}

		glog.V(2).Infof("moving %v from leased to free", ip)
		freeIPKey := h.prefix + "ips::free::" + ip.String()
		leasedIPKey := h.prefix + "ips::leased::" + ip.String()
		reservedIPKey := h.prefix + "ips::reserved::" + ip.String()

		res, err := kvc.Txn(ctx).If(
			etcdutil.KeyMissing(freeIPKey),
			etcdutil.KeyMissing(leasedIPKey),
			etcdutil.KeyMissing(reservedIPKey),
		).Then(
			etcd.OpPut(freeIPKey, ip.String()),
		).Commit()
		if err != nil {
			return errors.Wrap(err, "could not move ip to free state")
		}
		if res.Succeeded {
			glog.Infof("resurrected %v", ip)
		}
	}
	return nil
}

func getKeyExistenceMap(ctx context.Context, kvc *etcd.KV, prefix string) (*map[string]struct{}, error) {
	glog.V(2).Infof("listing keys under %v", prefix)
	resp, err := (*kvc).Get(ctx, prefix, etcd.WithPrefix())
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("could not list keys under %v", prefix))
	}

	existence := map[string]struct{}{}
	for _, kv := range resp.Kvs {
		key := string(kv.Key[len(prefix):])
		existence[key] = struct{}{}
	}

	return &existence, nil
}

func (h *DHCPHandler) nicLeasedIP(ctx context.Context, nic string) (net.IP, error) {
	kvc := etcd.NewKV(h.client)
	for _, k := range []string{"reserved", "leased"} {
		key := h.prefix + "nics::" + k + "::" + nic
		glog.V(2).Infof("GET %v", key)
		resp, err := kvc.Get(ctx, key)
		if err != nil {
			return nil, errors.Wrap(err, "could not get etcd key")
		}
		if len(resp.Kvs) > 0 {
			return parseIP4(string(resp.Kvs[0].Value)), nil
		}
	}
	return nil, nil
}

func (h *DHCPHandler) freeIP(ctx context.Context) (net.IP, error) {
	kvc := etcd.NewKV(h.client)
	prefix := h.prefix + "ips::free::"
	glog.V(2).Infof("GET PREFIX(%v)", prefix)
	resp, err := kvc.Get(ctx, prefix, etcd.WithPrefix(), etcd.WithSort(etcd.SortByKey, etcd.SortAscend))
	if err != nil {
		return nil, errors.Wrap(err, "could not get etcd key")
	}
	if len(resp.Kvs) == 0 {
		return nil, errors.New("no free IP addresses")
	}
	ip := string(resp.Kvs[0].Value)
	return parseIP4(ip), nil
}

func (h *DHCPHandler) leaseIP(ctx context.Context, ip net.IP, nic string, ttl time.Duration) error {
	lease, err := etcd.NewLease(h.client).Grant(ctx, int64(ttl.Seconds()))
	if err != nil {
		return errors.Wrap(err, "could not create new lease")
	}

	freeIPKey := h.prefix + "ips::free::" + ip.String()
	leasedIPKey := h.prefix + "ips::leased::" + ip.String()
	leasedNicKey := h.prefix + "nics::leased::" + nic
	reservedIPKey := h.prefix + "ips::reserved::" + ip.String()
	reservedNicKey := h.prefix + "nics::reserved::" + nic

	res, err := etcd.NewKV(h.client).Txn(ctx).If(
		// if the ip was previously free
		etcdutil.KeyExists(freeIPKey),
	).Then(
		etcd.OpTxn([]etcd.Cmp{
			etcdutil.KeyMissing(leasedIPKey),
			etcdutil.KeyMissing(leasedNicKey),
			etcdutil.KeyMissing(reservedIPKey),
			etcdutil.KeyMissing(reservedNicKey),
		}, []etcd.Op{
			// Unfree it, and associate it with this nic
			etcd.OpDelete(freeIPKey),
			etcd.OpPut(leasedIPKey, nic, etcd.WithLease(lease.ID)),
			etcd.OpPut(leasedNicKey, ip.String(), etcd.WithLease(lease.ID)),
		}, nil),
	).Else(
		etcd.OpTxn(
			[]etcd.Cmp{
				// check reservation for the NIC
				etcdutil.KeyExists(reservedNicKey),
			},
			[]etcd.Op{
				etcd.OpTxn(
					[]etcd.Cmp{
						// verify the request with the reservation
						etcd.Compare(etcd.Value(reservedIPKey), "=", nic),
						etcd.Compare(etcd.Value(reservedNicKey), "=", ip.String()),
					},
					[]etcd.Op{
						etcd.OpPut(leasedIPKey, nic, etcd.WithLease(lease.ID)),
						etcd.OpPut(leasedNicKey, ip.String(), etcd.WithLease(lease.ID)),
					},
					// An IP address is reserved for the NIC, but the requested address differs from that
					nil,
				),
			},
			[]etcd.Op{
				etcd.OpTxn(
					// Otherwise, we're _probably_ renewing it, so check that it's currently
					// associated with us
					[]etcd.Cmp{
						etcd.Compare(etcd.Value(leasedIPKey), "=", nic),
						etcd.Compare(etcd.Value(leasedNicKey), "=", ip.String()),
					},
					[]etcd.Op{
						etcd.OpPut(leasedIPKey, nic, etcd.WithLease(lease.ID)),
						etcd.OpPut(leasedNicKey, ip.String(), etcd.WithLease(lease.ID)),
					},
					nil,
				),
			},
		),
	).Commit()
	if err != nil {
		return errors.Wrap(err, "could not update for leased ip")
	}

	// If we did an else in the nested transaction, we failed to actually update
	// the lease
	nestedRes := res.Responses[0].Response.(*etcdpb.ResponseOp_ResponseTxn).ResponseTxn
	if res.Succeeded {
		// Then
		if !nestedRes.Succeeded {
			// Then -> Else
			return errors.New("ip is no longer free")
		}
	} else {
		// Else
		nestedRes2 := nestedRes.Responses[0].Response.(*etcdpb.ResponseOp_ResponseTxn).ResponseTxn
		if nestedRes.Succeeded {
			// Else -> Then
			if !nestedRes2.Succeeded {
				// Else -> Then -> Else
				return errors.New("A different address is reserved")
			}
		} else {
			// Else -> Else
			if !nestedRes2.Succeeded {
				// Else -> Else -> Else
				return errors.New("ip is no longer free")
			}
		}
	}

	return nil
}

func (h *DHCPHandler) revokeLease(ctx context.Context, nic string) error {
	kvc := etcd.NewKV(h.client)
	leasedNicKey := h.prefix + "nics::leased::" + nic
	res, err := kvc.Get(ctx, leasedNicKey)
	if err != nil {
		return errors.Wrap(err, "could not get nic's current lease")
	}
	ip := string(res.Kvs[0].Value)
	leasedIPKey := h.prefix + "ips::leased::" + ip
	freeIPKey := h.prefix + "ips::free::" + ip

	_, err = kvc.Txn(ctx).If(
		etcdutil.KeyExists(leasedIPKey),
		etcdutil.KeyExists(leasedNicKey),
	).Then(
		etcd.OpDelete(leasedIPKey),
		etcd.OpDelete(leasedNicKey),
		etcd.OpPut(freeIPKey, ip),
	).Commit()
	return errors.Wrap(err, "could not delete lease")
}

func (h *DHCPHandler) setHostname(ctx context.Context, nic string, hostname string, ttl time.Duration) error {
	lease, err := etcd.NewLease(h.client).Grant(ctx, int64(ttl.Seconds()))
	if err != nil {
		return errors.Wrap(err, "could not create new lease")
	}

	nic2hnKey := h.prefix + "nics::hostname::" + nic
	// Because several NICs can have the same hostname,
	// etcd key name contains NIC identifier as its suffix.
	hn2nicKey := h.prefix + "hostnames::nic::" + hostname + "::" + nic

	kvc := etcd.NewKV(h.client)
	resp, err := kvc.Get(ctx, nic2hnKey)
	if err != nil {
		return errors.Wrap(err, "could not search hostname for the NIC")
	}
	var existingHostname string
	if len(resp.Kvs) > 0 {
		existingHostname = string(resp.Kvs[0].Value)
	}

	var res *etcd.TxnResponse
	if existingHostname != "" && existingHostname != hostname {
		// If the NIC had different hostname previously,
		// it is necessary to delete records associated with old hostname
		existingHn2nicKey := h.prefix + "hostnames::nic::" + existingHostname + "::" + nic
		res, err = kvc.Txn(ctx).If(
			// Ensure the existence of keys and that hostname has not changed after the query.
			// If these conditions are unmet, do nothing and return error later.
			etcdutil.KeyExists(existingHn2nicKey),
			etcdutil.KeyExists(nic2hnKey),
			etcd.Compare(etcd.Value(nic2hnKey), "=", existingHostname),
		).Then(
			// Delete the existing assignment of hostname to the NIC, and associate new hostname and the NIC
			etcd.OpDelete(existingHn2nicKey),
			etcd.OpPut(nic2hnKey, hostname, etcd.WithLease(lease.ID)),
			etcd.OpPut(hn2nicKey, nic, etcd.WithLease(lease.ID)),
		).Commit()
	} else {
		// Otherwise, simply update keys associated with current hostname.
		res, err = kvc.Txn(ctx).If(
			// If keys have already exist and their values are different from the result of query
			// executed just before, there seems to be race condition.
			etcdutil.KeyExists(nic2hnKey),
			etcd.Compare(etcd.Value(nic2hnKey), "!=", hostname),
		).Then(
		// Do nothing because the conditions must not be satisfied
		).Else(
			etcd.OpPut(nic2hnKey, hostname, etcd.WithLease(lease.ID)),
			etcd.OpPut(hn2nicKey, nic, etcd.WithLease(lease.ID)),
		).Commit()
	}
	if err != nil {
		return errors.Wrap(err, "could not update hostname for the NIC")
	}
	if len(res.Responses) == 0 {
		return fmt.Errorf("The hostname for the NIC (%s) seems to have been changed.")
	}

	return nil
}

func (h *DHCPHandler) unsetHostname(ctx context.Context, nic string) error {
	nic2hnKey := h.prefix + "nics::hostname::" + nic

	kvc := etcd.NewKV(h.client)
	resp, err := kvc.Get(ctx, nic2hnKey)
	if err != nil {
		return errors.Wrap(err, "could not search hostname for the NIC")
	}
	if len(resp.Kvs) == 0 {
		// When no hostname has been assigned previously, do nothing
		return nil
	}
	existingHostname := string(resp.Kvs[0].Value)

	hn2nicKey := h.prefix + "hostnames::nic::" + existingHostname + "::" + nic

	res, err := kvc.Txn(ctx).If(
		// ensure the existence of the keys and that the hostname has not been changed
		etcdutil.KeyExists(nic2hnKey),
		etcdutil.KeyExists(hn2nicKey),
		etcd.Compare(etcd.Value(nic2hnKey), "=", existingHostname),
	).Then(
		etcd.OpDelete(nic2hnKey),
		etcd.OpDelete(hn2nicKey),
	).Commit()
	if len(res.Responses) == 0 {
		return fmt.Errorf("The hostname for the NIC (%s) seems to have been changed.")
	}

	return nil
}

func parseIP4(raw string) net.IP {
	ip := net.ParseIP(raw)
	if ip == nil {
		return nil
	}
	return ip[12:16]
}
