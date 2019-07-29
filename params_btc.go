package payment

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

var BtcTestNet3Params *chaincfg.Params = &chaincfg.TestNet3Params

func init() {
	hash, _ := chainhash.NewHashFromStr("000000000000004654a8d2599a24a95274f9d26c57be147e1c94324071d7363e") // bitcoin 1568498
	BtcTestNet3Params.Checkpoints = []chaincfg.Checkpoint{{1568498, hash}}
}
