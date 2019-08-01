package payment

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	bolt "github.com/etcd-io/bbolt"

	"github.com/bitmark-inc/exitwithstatus"
	"github.com/bitmark-inc/logger"
)

const checkpointBackTo = 2000
const MaximumOutboundPeers = 32
const PaymentExpiry = 12 * time.Hour
const HeaderSyncTimeout = time.Minute

var (
	ErrNoNewHeader        = errors.New("no new block headers from peer")
	ErrMissingBlockHeader = errors.New("missing previous block header")
	ErrTimeoutWaitHeader  = errors.New("timed out waiting for the block header data")
)

var srcAddr *wire.NetAddress = wire.NewNetAddressIPPort(net.ParseIP("0.0.0.0"), 18333, 0)

type PaymentWatcher struct {
	connectedPeers *PeerMap

	addrManager   *addrmgr.AddrManager
	connManager   *connmgr.ConnManager
	networkParams *chaincfg.Params
	checkpoint    chaincfg.Checkpoint
	storage       *PaymentStorage
	log           *logger.L

	lastHash     *chainhash.Hash
	lastHeight   int32
	onHeadersErr chan error
	stopping     bool
	stopChan     chan struct{}
}

func NewPaymentWatcher(networkParams *chaincfg.Params) *PaymentWatcher {
	var attemptLock sync.Mutex

	db, err := bolt.Open("btcd.db", 0600, nil)
	if err != nil {
		exitwithstatus.Message(err.Error())
	}

	addrManager := addrmgr.New(".", nil)
	checkpoint := networkParams.Checkpoints[len(networkParams.Checkpoints)-1]

	w := &PaymentWatcher{
		connectedPeers: NewPeerMap(),
		addrManager:    addrManager,
		networkParams:  networkParams,
		checkpoint:     checkpoint,
		storage:        NewPaymentStorage(db),
		log:            logger.New("payment"),
		onHeadersErr:   make(chan error, 0),
		stopChan:       make(chan struct{}, 0),
	}

	//	prepare configuration for the connection manager
	config := connmgr.Config{
		TargetOutbound:  MaximumOutboundPeers,
		OnConnection:    w.onConnectionConnected,
		OnDisconnection: w.onConnectionDisconnected,
		GetNewAddress: func() (net.Addr, error) {
			ka := addrManager.GetAddress()
			if ka == nil {
				return nil, errors.New("failed to find appropriate address to return")
			}
			address := ka.NetAddress()
			addr := &net.TCPAddr{
				Port: int(address.Port),
				IP:   address.IP,
			}
			attemptLock.Lock()
			defer attemptLock.Unlock()

			if time.Since(ka.LastAttempt()) < 10*time.Minute {
				return nil, errors.New("failed to find appropriate address to return")
			}

			if w.connectedPeers.Exist(addr.String()) {
				w.log.Warnf("ignore connected peer: %s", addr.String())
				return nil, errors.New("failed to find appropriate address to return")
			}

			addrManager.Attempt(address)
			return addr, nil
		},
		Dial: func(addr net.Addr) (net.Conn, error) {
			return net.Dial("tcp", addr.String())
		},
	}
	connManager, err := connmgr.New(&config)
	if err != nil {
		exitwithstatus.Message(err.Error())
	}

	w.connManager = connManager
	return w
}

// syncHeader will submit a `GetHeaders command to bitcoin peer and wait for its
// response to be processed
func (w *PaymentWatcher) syncHeaderFromPeer(p *peer.Peer) error {
	hash := w.lastHash

	if p.LastBlock() < w.lastHeight {
		var err error
		hash, err = w.storage.GetHash(p.LastBlock())

		if err != nil {
			return err
		}
	}

	w.log.Infof("Fetch headers from last block hash: %s", hash)
	headerMsg := wire.NewMsgGetHeaders()
	headerMsg.AddBlockLocatorHash(hash)
	p.QueueMessage(headerMsg, nil)

	select {
	case err := <-w.onHeadersErr:
		if err != nil {
			return err
		}
	case <-time.After(HeaderSyncTimeout):
		w.log.Warnf("Timed out waiting for the block header data")
		return ErrTimeoutWaitHeader
	}

	return nil
}

// QueryBlockDataByPeer will send GetData command to a peer
func (w *PaymentWatcher) QueryBlockDataByPeer(p *peer.Peer, hash *chainhash.Hash) {
	blockDataMsg := wire.NewMsgGetData()
	blockDataMsg.AddInvVect(&wire.InvVect{
		Type: wire.InvTypeBlock,
		Hash: *hash,
	})

	p.QueueMessage(blockDataMsg, nil)
}

// lookupPayment will trigger a block re-scan process to check potential payments
// back to certains blocks
func (w *PaymentWatcher) lookupPaymentFromPeer(p *peer.Peer, lookUpToHeight int32) {
	if lookUpToHeight == 0 {
		return
	}

	if p != nil {
		w.log.Infof("Look up payments by height from: %d, to: %d\n", lookUpToHeight, w.lastHeight)
		for h := w.lastHeight; h >= lookUpToHeight; h-- {
			hash, err := w.storage.GetHash(h)
			if err != nil {
				fmt.Println("error", err)
				return
			}

			if hash == nil {
				fmt.Println("WARN: should not have empty hash. is something missing?")
			}

			w.log.Debugf("Fetch block data of block: %d %s", h, hash)
			w.QueryBlockDataByPeer(p, hash)
		}
	}
}

// fetchMoreAddress will fetch new messages from the bitcoin network
func (w *PaymentWatcher) fetchMoreAddress() {
	for {
		if w.addrManager.NeedMoreAddresses() {
			w.log.Debugf("Need more address. Fetch address from peers.")

			w.connectedPeers.Iter(func(k string, p *peer.Peer) {
				p.QueueMessage(wire.NewMsgGetAddr(), nil)
			})
		}
		time.Sleep(10 * time.Second)
	}
}

func (w *PaymentWatcher) sync() {
	for {
	SYNC_LOOP:
		for {
			p := w.getPeer()
			w.log.Infof("Peer block height: %d, our block height: %d", p.LastBlock(), w.lastHeight)

			err := w.syncHeaderFromPeer(p)
			if err != nil {
				switch err {
				case ErrNoNewHeader:
					w.log.Debug(err.Error())
					if p.LastBlock() < w.lastHeight {
						p.Disconnect()
					} else {
						time.Sleep(10 * time.Second)
					}
				case ErrMissingBlockHeader:
					w.log.Warnf("Incorrect block data", err.Error())
					break SYNC_LOOP
				}
			} else {
				if p.LastBlock() <= w.lastHeight {
					time.Sleep(20 * time.Second)
				}
			}
		}

		if err := w.rollbackBlock(); err != nil {
			w.log.Errorf("Fail to rollback blocks. Error: %s", err)
		}
	}
}

func (w *PaymentWatcher) Start(firstAddress string) error {
	err := w.storage.Init()
	if err != nil {
		return fmt.Errorf("unable to init storage. reason: %s", err)
	}

	lastHash, err := w.storage.GetCheckpoint()
	if err != nil {
		w.log.Warnf("unable to get last hash: %s", err)
	}

	if lastHash != nil {
		lastHeight, err := w.storage.GetHeight(lastHash)
		if err != nil {
			w.log.Warnf("unable to get last hash: %s", err)
		} else {
			w.lastHash = lastHash
			w.lastHeight = lastHeight
		}
	}

	// Since lastHeight is zero, we will reset the data from the checkpoint
	if w.lastHeight == 0 {
		w.lastHash = w.checkpoint.Hash
		w.lastHeight = w.checkpoint.Height

		// Write the first hash data into storage
		if err := w.storage.StoreBlock(w.lastHeight, w.lastHash); err != nil {
			return fmt.Errorf("unable to set first hash: %s", err)
		}
	}

	w.log.Infof("last hash: %s, last block height: %d", w.lastHash, w.lastHeight)

	w.addrManager.Start()

	// add peer address by dns seed
	for _, seed := range w.networkParams.DNSSeeds {
		ips, err := net.LookupIP(seed.Host)
		if err != nil {
			w.log.Warnf("Fail to look up ip from DNS. Error: %s", err)
			continue
		}
		for i, ip := range ips {
			// use DNS seed as a peer up to half of target outbound peer amounts
			if i > MaximumOutboundPeers/2 {
				break
			}
			if err := w.addrManager.AddAddressByIP(net.JoinHostPort(ip.String(), w.networkParams.DefaultPort)); err != nil {
				w.log.Warnf("Can not add an IP into address manager. Error: %s", err)
			}

		}
	}
	if firstAddress != "" {
		w.addrManager.AddAddressByIP(firstAddress)
	}

	w.connManager.Start()

	go func() {
		for {
			w.log.Infof("Connected Peers: %d", w.connectedPeers.Len())
			// w.connectedPeers.Iter(func(k string, v *peer.Peer) {
			// 	w.log.Info("Peer Last Block:", v.LastBlock())
			// })
			time.Sleep(30 * time.Second)
		}
	}()

	go w.fetchMoreAddress()
	go w.sync()

	return nil
}

func (w *PaymentWatcher) Stop() {
	if w.stopping {
		return
	}
	w.connManager.Stop()
	w.addrManager.Stop()

	defer func() { w.stopChan <- struct{}{} }()

	if w.lastHeight == 0 || w.lastHeight == w.checkpoint.Height {
		return
	}

	if err := w.storage.SetCheckpoint(w.lastHeight); err != nil {
		w.log.Errorf("Can not update the new check point. Error: %s", err)
	}
}

func (w *PaymentWatcher) StopChan() chan struct{} {
	return w.stopChan
}

// getPeer will return a peer from connected peer randomly by the
// iteration of a map
// Note: This is not a perfect random mechanism. But what we need is
// to have a way to have chances to get peers from different sources.
func (w *PaymentWatcher) getPeer() *peer.Peer {
	for {
		p := w.connectedPeers.First()
		if p == nil {
			time.Sleep(time.Second)
			continue
		}

		if w.lastHeight-p.LastBlock() > 100 {
			p.Disconnect()
			w.log.Tracef("Disconnect out-date peer: %s", p.Addr())
			time.Sleep(time.Second)
			continue
		}

		return p
	}
}

func (w *PaymentWatcher) onPeerVerAck(p *peer.Peer, msg *wire.MsgVerAck) {
	if w.connectedPeers.Exist(p.Addr()) {
		w.log.Tracef("Drop duplicated connection: %s", p.Addr())
		p.Disconnect()
		return
	}

	w.connectedPeers.Add(p.Addr(), p)
	w.addrManager.Good(p.NA())

	w.log.Tracef("Complete neogotiation with the peer: %s", p.Addr())
}

// onPeerAddr will add discovered new addresses into address manager
func (w *PaymentWatcher) onPeerAddr(p *peer.Peer, msg *wire.MsgAddr) {
	for _, a := range msg.AddrList {
		w.log.Tracef("Receive new address: %s:%d. Peer service: %s", a.IP, a.Port, a.Services)
		w.addrManager.AddAddress(a, srcAddr)
	}
}

// onPeerHeaders handles messages from peer for updating header data
func (w *PaymentWatcher) onPeerHeaders(p *peer.Peer, msg *wire.MsgHeaders) {
	var err error
	defer func() {
		select {
		case w.onHeadersErr <- err:
		}
	}()

	if len(msg.Headers) == 0 {
		err = ErrNoNewHeader
		return
	}

	var hasNewHeader bool
	var newHash chainhash.Hash
	var firstNewHeight, newHeight int32

	for _, h := range msg.Headers {
		newHash = h.BlockHash()
		newHashByte := newHash.CloneBytes()

		newHeight, _ = w.storage.GetHeight(&newHash)

		if newHeight != 0 {
			if time.Since(h.Timestamp) < 48*time.Hour && firstNewHeight == 0 {
				firstNewHeight = newHeight
			}
			hash, _ := w.storage.GetHash(newHeight)
			if reflect.DeepEqual(hash.CloneBytes(), newHashByte) {
				w.log.Tracef("Omit the same hash: %s", hash)
				continue
			}
		}

		hasNewHeader = true

		prevHeight, err := w.storage.GetHeight(&h.PrevBlock)
		if err != nil {
			p.Disconnect()
			err = ErrMissingBlockHeader
			return
		}

		newHeight = prevHeight + 1

		if time.Since(h.Timestamp) < 48*time.Hour && firstNewHeight == 0 {
			firstNewHeight = newHeight
		}

		w.log.Debugf("Add block hash: %s, %d", newHash, newHeight)
		if err = w.storage.StoreBlock(newHeight, &newHash); err != nil {
			return
		}
	}

	if !hasNewHeader {
		err = ErrNoNewHeader
	}

	if firstNewHeight > 0 {
		// TODO: look up from range instead of from the latest because there will be a race condition
		go w.lookupPaymentFromPeer(p, firstNewHeight)
	}

	if newHeight > p.LastBlock() {
		p.UpdateLastBlockHeight(newHeight)
		p.UpdateLastAnnouncedBlock(&newHash)
	}
	w.lastHash = &newHash
	w.lastHeight = newHeight
}

type PaymentInfo struct {
	BlockHash string
	TxId      string
	Payments  map[string]int64
	Timestamp time.Time
}

func (w *PaymentWatcher) rollbackBlock() error {
	deleteDownTo := w.lastHeight - checkpointBackTo

	// prevent from rolling back too much blocks
	if deleteDownTo < w.checkpoint.Height {
		deleteDownTo = w.checkpoint.Height
	}

	w.log.Infof("Start rolling back blocks to: %d", deleteDownTo)
	if err := w.storage.RollbackTo(w.lastHeight, deleteDownTo); err != nil {
		return err
	}

	lastHash, err := w.storage.GetHash(deleteDownTo)
	if err != nil {
		return err
	}

	w.lastHash = lastHash
	w.lastHeight = deleteDownTo
	return nil
}

// onPeerBlock handles block messages from peer. It abstrcts transactions from block data to
// collect all potential bitmark payment transactions.
func (w *PaymentWatcher) onPeerBlock(p *peer.Peer, msg *wire.MsgBlock, buf []byte) {
	w.log.Tracef("on block: %s", msg.BlockHash())

	if time.Since(msg.Header.Timestamp) > PaymentExpiry {
		w.log.Tracef("ignore old block: %s", msg.BlockHash().String())
		return
	}

	hash := msg.BlockHash()
	blockHeight, _ := w.storage.GetHeight(&hash)
	if blockHeight == 0 {
		return
	}

	if w.storage.HasBlockReceipt(blockHeight) {
		w.log.Tracef("block has already processed: %d", blockHeight)
		return
	}

	// have height
	// does not have height

	for _, tx := range msg.Transactions {
		var payId []byte
		payments := map[string]int64{}

		for _, txout := range tx.TxOut {
			// if script starts with `6a30`, the rest of bytes would be a potential payment id
			index := bytes.Index(txout.PkScript, []byte{106, 48})
			if index == 0 {
				payId = txout.PkScript[2:]
			} else {
				s, err := txscript.ParsePkScript(txout.PkScript)
				if err != nil {
					continue
				}

				addr, err := s.Address(w.networkParams)
				if err != nil {
					continue
				}
				payments[addr.String()] = txout.Value
			}
		}

		if payId != nil {
			paymentInfo := PaymentInfo{
				BlockHash: msg.BlockHash().String(),
				TxId:      tx.TxHash().String(),
				Payments:  payments,
				Timestamp: msg.Header.Timestamp,
			}

			w.log.Infof("Find a potential payment. paymentId: %s, paymentInfo: %+v", hex.EncodeToString(payId), paymentInfo)

			if err := w.storage.StorePayment(payId, paymentInfo); err != nil {
				w.log.Errorf("Can not save payments: %+v. Error: %s", paymentInfo, err)
				continue
			}
		}
	}

	// add a receipt for processed blocks
	if err := w.storage.SetBlockReceipt(blockHeight); err != nil {
		w.log.Errorf("Can not set block processed. Error: %s", err)
	}
}

// peerConfig returns a payment template. The `ChainParams` will vary between
// different network settings in `PaymentWatcher`.
func (w *PaymentWatcher) peerConfig() *peer.Config {
	return &peer.Config{
		UserAgentName:    "bitmarkd-payment-lightclient",
		UserAgentVersion: "0.1.0",
		ChainParams:      w.networkParams,
		DisableRelayTx:   true,
		Services:         0,
		Listeners: peer.MessageListeners{
			OnVersion: func(p *peer.Peer, msg *wire.MsgVersion) *wire.MsgReject {
				return nil
			},
			OnVerAck:  w.onPeerVerAck,
			OnAddr:    w.onPeerAddr,
			OnHeaders: w.onPeerHeaders,
			OnBlock:   w.onPeerBlock,

			OnTx: func(p *peer.Peer, msg *wire.MsgTx) {
				w.log.Debugf("tx: %+v", msg)
			},
			OnAlert: func(p *peer.Peer, msg *wire.MsgAlert) {
				w.log.Debugf("alert: %+v", msg)
			},
			OnNotFound: func(p *peer.Peer, msg *wire.MsgNotFound) {
				w.log.Debugf("not found: %+v", msg)
			},
			OnReject: func(p *peer.Peer, msg *wire.MsgReject) {
				w.log.Debugf("reject: %+v", msg)
			},
		},
	}
}

// peerNeogotiate will neogotiate with the remote peer to complete the connection
func (w *PaymentWatcher) peerNeogotiate(conn net.Conn) (*peer.Peer, error) {
	ipAddr := conn.RemoteAddr().String()
	p, err := peer.NewOutboundPeer(w.peerConfig(), ipAddr)
	if err != nil {
		return nil, err
	}
	w.addrManager.Connected(p.NA())

	w.log.Tracef("Try to associate connection to: %s", ipAddr)
	p.AssociateConnection(conn)

	return p, nil
}

// onConnectionConnected is callback function which is invoked by connection manager when
// a peer connection has successfully established.
func (w *PaymentWatcher) onConnectionConnected(connReq *connmgr.ConnReq, conn net.Conn) {
	p, err := w.peerNeogotiate(conn)
	if err != nil {
		w.log.Warnf("Peer: %s neogotiation failed. Error: %s", connReq.Addr.String(), err)
		w.connManager.Disconnect(connReq.ID())
	}

	// To info connection manager that a connection is terminated
	go func() {
		p.WaitForDisconnect()
		w.connManager.Disconnect(connReq.ID())
	}()
}

// onConnectionDisconnected is callback function which is invoked by connection manager when
// one of its connection request is disconnected.
func (w *PaymentWatcher) onConnectionDisconnected(connReq *connmgr.ConnReq) {
	w.log.Debugf("Clean up disconnected peer: %s", connReq.Addr.String())
	w.connectedPeers.Delete(connReq.Addr.String())
}
