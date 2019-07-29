package payment

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"reflect"
	"strconv"
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
	db            *bolt.DB

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
		log.Fatal(err)
	}

	addrManager := addrmgr.New("addrCache", nil)
	checkpoint := networkParams.Checkpoints[len(networkParams.Checkpoints)-1]

	w := &PaymentWatcher{
		connectedPeers: NewPeerMap(),
		addrManager:    addrManager,
		networkParams:  networkParams,
		checkpoint:     checkpoint,
		storage:        NewPaymentStorage(db),
		db:             db,
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
				// log.Println("ignore connected peer:", addr.String())
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
		log.Fatal(err)
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

	log.Println("syn from block header:", hash)
	headerMsg := wire.NewMsgGetHeaders()
	headerMsg.AddBlockLocatorHash(hash)
	p.QueueMessage(headerMsg, nil)

	select {
	case err := <-w.onHeadersErr:
		if err != nil {
			return err
		}
	case <-time.After(HeaderSyncTimeout):
		log.Println("timed out waiting for the block header data")
		return ErrTimeoutWaitHeader
	}

	return nil
}

// lookupPayment will trigger a block re-scan process to check potential payments
// back to certains blocks
func (w *PaymentWatcher) lookupPaymentFromPeer(p *peer.Peer, lookUpToHeight int32) {
	if lookUpToHeight == 0 {
		return
	}

	if p != nil {
		// Use `Update` to prevent race condition
		w.db.Update(func(tx *bolt.Tx) error {
			lastHeight := []byte(fmt.Sprintf("%08x", w.lastHeight))
			startHeight := []byte(fmt.Sprintf("%08x", lookUpToHeight))
			c := tx.Bucket(HeightBucket).Cursor()
			log.Printf("look up payments by height from: %d, to: %d\n", lookUpToHeight, w.lastHeight)
			// Seek returns the last query key, the key might not be the latest
			for k, v := c.Seek(lastHeight); k != nil && bytes.Compare(k, startHeight) >= 0; k, v = c.Prev() {
				hash, err := chainhash.NewHash(v)
				if err != nil {
					fmt.Println("error", err)
				}

				// FIXME: debugging
				// i, _ := strconv.ParseInt(string(k), 16, 32)
				// log.Println("Check block data:", hash, i)

				blockDataMsg := wire.NewMsgGetData()
				blockDataMsg.AddInvVect(&wire.InvVect{
					Type: wire.InvTypeBlock,
					Hash: *hash,
				})

				p.QueueMessage(blockDataMsg, nil)
			}
			return nil
		})
	}
}

// fetchMoreAddress will fetch new messages from the bitcoin network
func (w *PaymentWatcher) fetchMoreAddress() {
	for {
		if w.addrManager.NeedMoreAddresses() {
			log.Println("need more address. broadcast GetAddr to peers")

			w.connectedPeers.Iter(func(k string, p *peer.Peer) {
				p.QueueMessage(wire.NewMsgGetAddr(), nil)
			})
		}
		time.Sleep(10 * time.Second)
	}
}

func (w *PaymentWatcher) ValidatePayment(payId string) (isValid bool) {
	height, _, err := w.storage.GetPayment(payId)
	if err != nil {
		return
	}

	if w.lastHeight-int32(height) >= 2 {
		isValid = true
	}

	return
}

func (w *PaymentWatcher) sync() {
	for {
		for {
			p := w.getPeer()
			log.Println(p, "height:", p.LastBlock(), "last height:", w.lastHeight)

			err := w.syncHeaderFromPeer(p)
			if err != nil {
				log.Println(err)
				switch err {
				case ErrNoNewHeader:
					if p.LastBlock() < w.lastHeight {
						p.Disconnect()
					} else {
						time.Sleep(20 * time.Second)
					}
				case ErrMissingBlockHeader:
					break
				}
			} else {
				if p.LastBlock() <= w.lastHeight {
					time.Sleep(20 * time.Second)
				}
			}
		}

		err := w.rollbackBlock()
		log.Println("rollback error:", err)
	}
}

func (w *PaymentWatcher) Start(firstAddress string) {
	err := w.storage.Init()
	if err != nil {
		log.Fatal("unable to init storage:", err)
	}

	lastHash, err := w.storage.GetCheckpoint()
	if err != nil {
		log.Fatal("unable to get last hash:", err)
	}

	if lastHash == nil {
		w.lastHash = w.checkpoint.Hash
		w.lastHeight = w.checkpoint.Height

		// Write the first hash data into
		if err := w.storage.StoreBlock(w.lastHeight, w.lastHash); err != nil {
			log.Fatal("unable to set first hash:", err)
		}
	} else {
		lastHeight, err := w.storage.GetHeight(lastHash)
		if err != nil {
			log.Fatal("unable to get last hash: ", err)
		}

		w.lastHash = lastHash
		w.lastHeight = lastHeight
	}

	log.Println("last hash:", w.lastHash)
	log.Println("last block height:", w.lastHeight)

	w.addrManager.Start()

	// add peer address by dns seed
	for _, seed := range w.networkParams.DNSSeeds {
		ips, err := net.LookupIP(seed.Host)
		if err != nil {
			// FIXME: warn log
			log.Println(err)
			continue
		}
		for i, ip := range ips {
			// use DNS seed as a peer up to half of target outbound peer amounts
			if i > MaximumOutboundPeers/2 {
				break
			}
			w.addrManager.AddAddressByIP(net.JoinHostPort(ip.String(), w.networkParams.DefaultPort))
		}
	}
	if firstAddress != "" {
		w.addrManager.AddAddressByIP(firstAddress)
	}

	w.connManager.Start()

	go func() {
		for {
			log.Println("Connected Peers:", w.connectedPeers.Len())
			// w.connectedPeers.Iter(func(k string, v *peer.Peer) {
			// 	log.Println("Peer Last Block:", v.LastBlock())
			// })
			time.Sleep(30 * time.Second)
		}
	}()

	go w.fetchMoreAddress()
	go w.sync()
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

	err := w.storage.SetCheckpoint(w.lastHeight)
	if err != nil {
		log.Fatal("can not update the new check point")
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
			log.Println("disconnect out-date peer")
			time.Sleep(time.Second)
			continue
		}

		return p
	}
}

func (w *PaymentWatcher) onPeerVerAck(p *peer.Peer, msg *wire.MsgVerAck) {
	if w.connectedPeers.Exist(p.Addr()) {
		log.Println("drop duplicated connection")
		p.Disconnect()
		return
	}

	w.connectedPeers.Add(p.Addr(), p)
	w.addrManager.Good(p.NA())

	// FIXME: debug log
	// log.Println("Complete handshake with peer:", p.Addr())
}

// onPeerAddr will add discovered new addresses into address manager
func (w *PaymentWatcher) onPeerAddr(p *peer.Peer, msg *wire.MsgAddr) {
	// log.Println("OnAddr: address count:", len(msg.AddrList))
	for _, a := range msg.AddrList {
		// filter addresses
		// log.Println("Receive Addr:", a.Services, a.IP, a.Port)
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
	if err = w.db.Update(func(tx *bolt.Tx) error {
		headers := tx.Bucket(HeaderBucket)
		heights := tx.Bucket(HeightBucket)

		for _, h := range msg.Headers {
			newHash = h.BlockHash()
			newHashByte := newHash.CloneBytes()

			// check if current height has already existed
			if heightByte := headers.Get(newHashByte); heightByte != nil {
				currentHeight, err := strconv.ParseInt(string(heightByte), 16, 32)
				if err != nil {
					return err
				}

				newHeight = int32(currentHeight)

				if time.Since(h.Timestamp) < 48*time.Hour && firstNewHeight == 0 {
					firstNewHeight = newHeight
				}

				if reflect.DeepEqual(heights.Get(heightByte), newHashByte) {
					// FIXME: debug log
					// log.Println("omit the same hash", newHash)
					continue
				}
			}

			hasNewHeader = true
			prevHeightByte := headers.Get(h.PrevBlock.CloneBytes())

			if prevHeightByte == nil {
				p.Disconnect()
				return ErrMissingBlockHeader
			}

			prevHeight, err := strconv.ParseInt(string(prevHeightByte), 16, 32)
			if err != nil {
				return err
			}

			newHeight = int32(prevHeight) + 1

			if time.Since(h.Timestamp) < 48*time.Hour && firstNewHeight == 0 {
				firstNewHeight = newHeight
			}

			// FIXME: temp hide
			log.Println("Add block hash:", newHash, newHeight)
			if err := headers.Put(newHash.CloneBytes(), []byte(fmt.Sprintf("%08x", newHeight))); err != nil {
				return err
			}
			if err := heights.Put([]byte(fmt.Sprintf("%08x", newHeight)), newHash.CloneBytes()); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		log.Println("fail to update hash: ", err)
		return
	}

	if !hasNewHeader {
		err = ErrNoNewHeader
	}

	if firstNewHeight > 0 {
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
	deleteDownTo := w.checkpoint.Height - checkpointBackTo
	log.Println("start rollback blocks: ", deleteDownTo)

	w.storage.RollbackTo(w.lastHeight, deleteDownTo)

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
	// log.Println("on block", msg.BlockHash())

	if time.Since(msg.Header.Timestamp) > PaymentExpiry {
		// log.Println("ignore old block:", msg.BlockHash().String())
		return
	}

	hash := msg.BlockHash()
	blockHeight, _ := w.storage.GetHeight(&hash)
	if blockHeight == 0 {
		return
	}

	if w.storage.HasReceipt(blockHeight) {
		// log.Println("block has already processed:", blockHeight)
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

			log.Printf("Find a potential payment. paymentId: %s, paymentInfo: %+v", hex.EncodeToString(payId), paymentInfo)

			if err := w.storage.StorePayment(payId, paymentInfo); err != nil {
				log.Println("can not save payments:", paymentInfo, "error:", err)
				continue
			}
		}
	}

	// add a receipt for processed blocks
	if err := w.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(ReceiptBucket)
		return bucket.Put([]byte(fmt.Sprintf("%08x", blockHeight)), []byte{})
	}); err != nil {
		log.Println("can not set block processed:", err)
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
				log.Println("tx:", msg)
			},
			OnAlert: func(p *peer.Peer, msg *wire.MsgAlert) {
				log.Println("alert:", msg)
			},
			OnNotFound: func(p *peer.Peer, msg *wire.MsgNotFound) {
				log.Println("not found:", msg)
			},
			OnReject: func(p *peer.Peer, msg *wire.MsgReject) {
				log.Println("reject:", msg)
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

	// FIXME: add to debug log
	// log.Println("Try to associate connection to:", ipAddr)
	p.AssociateConnection(conn)

	return p, nil
}

// onConnectionConnected is callback function which is invoked by connection manager when
// a peer connection has successfully established.
func (w *PaymentWatcher) onConnectionConnected(connReq *connmgr.ConnReq, conn net.Conn) {
	p, err := w.peerNeogotiate(conn)
	if err != nil {
		w.connManager.Disconnect(connReq.ID())
	}

	// info connection manager that a connection is terminated
	go func() {
		p.WaitForDisconnect()
		w.connManager.Disconnect(connReq.ID())
	}()
}

// onConnectionDisconnected is callback function which is invoked by connection manager when
// one of its connection request is disconnected.
func (w *PaymentWatcher) onConnectionDisconnected(connReq *connmgr.ConnReq) {
	log.Println("clean up disconnected peer:", connReq.Addr.String())
	w.connectedPeers.Delete(connReq.Addr.String())
}
