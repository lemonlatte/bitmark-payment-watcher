package payment

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strconv"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	bolt "github.com/etcd-io/bbolt"
)

var HeaderBucket = []byte("headers")
var HeightBucket = []byte("heights")
var ReceiptBucket = []byte("receipts")
var PaymentsBucket = []byte("payments")

var CheckpointKey = []byte("checkpoint")

type PaymentStorage struct {
	boltdb *bolt.DB
}

func NewPaymentStorage(db *bolt.DB) *PaymentStorage {
	return &PaymentStorage{
		boltdb: db,
	}
}

func (s *PaymentStorage) Init() error {
	return s.boltdb.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(HeaderBucket); err != nil {
			return err
		}

		if _, err := tx.CreateBucketIfNotExists(HeightBucket); err != nil {
			return err
		}

		if _, err := tx.CreateBucketIfNotExists(PaymentsBucket); err != nil {
			return err
		}

		if _, err := tx.CreateBucketIfNotExists(ReceiptBucket); err != nil {
			return err
		}

		return nil
	})
}

// GetHeight returns height for a specific hash
func (s *PaymentStorage) GetHeight(hash *chainhash.Hash) (int32, error) {
	var height int32

	if hash == nil {
		return 0, errors.New("hash can not be nil")
	}

	if err := s.boltdb.View(func(tx *bolt.Tx) error {
		var err error
		bucket := tx.Bucket(HeaderBucket)
		heightByte := bucket.Get(hash.CloneBytes())

		if heightByte == nil {
			return nil
		}

		_height, err := strconv.ParseInt(string(heightByte), 16, 32)
		if err != nil {
			return err
		}

		height = int32(_height)

		return nil
	}); err != nil {
		return 0, err
	}

	return height, nil
}

// GetCheckpoint returns the hash of the last saved checkpoint in the storage
func (s *PaymentStorage) GetCheckpoint() (*chainhash.Hash, error) {
	var hash *chainhash.Hash
	if err := s.boltdb.View(func(tx *bolt.Tx) (err error) {

		headers := tx.Bucket(HeaderBucket)
		h := headers.Get(CheckpointKey)

		if h == nil {
			return nil
		}

		hash, err = chainhash.NewHash(h)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return hash, nil
}

// SetCheckpoint saves the hash of a give height as a checkpoint
func (s *PaymentStorage) SetCheckpoint(height int32) error {
	return s.boltdb.Update(func(tx *bolt.Tx) (err error) {
		headers := tx.Bucket(HeaderBucket)
		heights := tx.Bucket(HeightBucket)

		checkpointHeight := checkpointBackTo * (height / checkpointBackTo)
		hash := heights.Get([]byte(fmt.Sprintf("%08x", checkpointHeight)))
		if hash == nil {
			return errors.New("block height is not found")
		}

		return headers.Put(CheckpointKey, hash)
	})
}

// GetHash returns the hash of a give height
func (s *PaymentStorage) GetHash(height int32) (*chainhash.Hash, error) {
	var hash *chainhash.Hash
	if err := s.boltdb.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(HeightBucket)
		h, err := chainhash.NewHash(bucket.Get([]byte(fmt.Sprintf("%08x", height))))
		if err != nil {
			return err
		}
		hash = h
		return nil
	}); err != nil {
		return nil, err
	}
	return hash, nil
}

// StoreBlock saves a pair of hash and its height
func (s *PaymentStorage) StoreBlock(height int32, hash *chainhash.Hash) error {
	return s.boltdb.Update(func(tx *bolt.Tx) error {
		headers := tx.Bucket(HeaderBucket)
		heights := tx.Bucket(HeightBucket)

		if err := headers.Put(hash.CloneBytes(), []byte(fmt.Sprintf("%08x", height))); err != nil {
			return err
		}
		if err := heights.Put([]byte(fmt.Sprintf("%08x", height)), hash.CloneBytes()); err != nil {
			return err
		}
		return nil
	})
}

// RollbackTo deletes blocks from a block down a another
func (s *PaymentStorage) RollbackTo(deleteFrom, deleteTo int32) error {
	if deleteFrom <= deleteTo {
		return errors.New("incorrect range to blocks to rollback")
	}

	return s.boltdb.Update(func(tx *bolt.Tx) error {
		heights := tx.Bucket(HeightBucket)
		headers := tx.Bucket(HeaderBucket)

		for i := deleteFrom; i > deleteTo; i-- {
			fmt.Println("delete block:", i)
			heightsByte := []byte(fmt.Sprintf("%08x", i))
			hashByte := heights.Get(heightsByte)
			if err := heights.Delete(heightsByte); err != nil {
				return err
			}
			if err := headers.Delete(hashByte); err != nil {
				return err
			}
		}
		return nil
	})

}

// SetBlockReceipt will mark a given block as processed
func (s *PaymentStorage) SetBlockReceipt(height int32) error {
	return s.boltdb.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(ReceiptBucket)
		return bucket.Put([]byte(fmt.Sprintf("%08x", height)), []byte{})
	})
}

// HasBlockReceipt validate whether a given block is processed by checking its receipt
func (s *PaymentStorage) HasBlockReceipt(height int32) bool {
	var hasReceipt bool

	s.boltdb.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(ReceiptBucket)
		if r := bucket.Get([]byte(fmt.Sprintf("%08x", height))); r != nil {
			hasReceipt = true
		}
		return nil
	})

	return hasReceipt
}

// StorePayment saves payment information for a pay id.
func (s *PaymentStorage) StorePayment(payId []byte, payInfo PaymentInfo) error {
	b, err := json.Marshal(payInfo)
	if err != nil {
		return err
	}

	return s.boltdb.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(PaymentsBucket)
		return bucket.Put(payId, b)
	})
}

// GetPayment get payment information by a pay id.
func (s *PaymentStorage) GetPayment(payId string) (height int32, payInfo PaymentInfo, err error) {
	id, err := hex.DecodeString(payId)
	if err != nil {
		log.Println("invalid payment id: ", err)
		return
	}

	if err := s.boltdb.View(func(tx *bolt.Tx) error {
		payments := tx.Bucket(PaymentsBucket)
		headers := tx.Bucket(HeaderBucket)
		heights := tx.Bucket(HeightBucket)
		b := payments.Get(id)

		if b == nil {
			return errors.New("payment not found")
		}

		if err := json.Unmarshal(b, &payInfo); err != nil {
			return err
		}

		hash, err := chainhash.NewHashFromStr(payInfo.BlockHash)
		if err != nil {
			return err
		}

		hashByte := hash.CloneBytes()

		heightByte := headers.Get(hashByte)
		if heightByte == nil {
			return errors.New("missing block height")
		}

		if !reflect.DeepEqual(hashByte, heights.Get(heightByte)) {
			return errors.New("the block hash does not match the current hash of its block height")
		}

		paymentHeight, err := strconv.ParseInt(string(heightByte), 16, 32)
		if err != nil {
			return err
		}

		height = int32(paymentHeight)
		return nil
	}); err != nil {
		log.Println("unable to validate payments: ", err)
		return 0, PaymentInfo{}, err
	}

	return
}
