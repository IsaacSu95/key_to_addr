package key_to_addr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	dashbtcutil "github.com/dashpay/dashd-go/btcutil"
	chaincfgdash "github.com/dashpay/dashd-go/chaincfg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	bchChaincfg "github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchutil"
)

type Key struct {
	pubkey      string
	ethAddr     string
	btcAddr     string
	bchAddr     string
	tronAddress string
	dashAddress string
	dogeAddress string
}

func NewKey(pubkey string) (*Key, error) {
	k := &Key{pubkey: pubkey}
	if err := k.newETHAddress(); err != nil {
		return nil, err
	}
	if err := k.newBTCAddress(); err != nil {
		return nil, err
	}
	if err := k.newTrxAddress(); err != nil {
		return nil, err
	}
	if err := k.newBCHAddress(); err != nil {
		return nil, err
	}
	if err := k.newDashAddress(); err != nil {
		return nil, err
	}
	if err := k.newDogeAddress(); err != nil {
		return nil, err
	}

	return k, nil
}
func (k *Key) newETHAddress() error {
	res2, err := hex.DecodeString(k.pubkey)
	if err != nil {
		return err
	}
	addr := common.BytesToAddress(crypto.Keccak256(res2[1:])[12:])
	k.ethAddr = addr.String()
	return nil
}
func (k *Key) ETHAddress() string {
	return k.ethAddr
}

func (k *Key) newBTCAddress() error {
	res2, err := hex.DecodeString(k.pubkey)
	if err != nil {
		return err
	}
	witnessProg := btcutil.Hash160(res2)
	addressWitnessPubKeyHash, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, &chaincfg.MainNetParams)
	if err != nil {
		return err
	}
	serializedScript, err := txscript.PayToAddrScript(addressWitnessPubKeyHash)
	if err != nil {
		return err
	}
	addressScriptHash, err := btcutil.NewAddressScriptHash(serializedScript, &chaincfg.MainNetParams)
	if err != nil {
		return err
	}
	k.btcAddr = addressScriptHash.EncodeAddress()

	return nil
}
func (k *Key) BTCAddress() string {
	return k.btcAddr
}

func (k *Key) newBCHAddress() error {
	res2, err := hex.DecodeString(k.pubkey)
	if err != nil {
		return err
	}
	pubkey, err := btcec.ParsePubKey(res2)
	if err != nil {
		return err
	}
	pubKeyHash := bchutil.Hash160(pubkey.SerializeCompressed())
	addr, err := bchutil.NewAddressPubKeyHash(pubKeyHash,
		&bchChaincfg.MainNetParams)
	if err != nil {
		return err
	}
	k.bchAddr = addr.String()
	//addr, _ := bchutil.NewAddressPubKey(res2, &bchChaincfg.MainNetParams)
	//k.bchAddr = addr.EncodeAddress()
	return nil
}
func (k *Key) BCHAddress() string {
	return k.bchAddr
}

func (k *Key) newTrxAddress() error {
	res2, err := hex.DecodeString(k.pubkey)
	if err != nil {
		return err
	}
	address := common.BytesToAddress(crypto.Keccak256(res2[1:])[12:]).Hex()
	address = "41" + address[2:]
	addb, err := hex.DecodeString(address)
	if err != nil {
		return err
	}
	firstHash := sha256.Sum256(addb)
	secondHash := sha256.Sum256(firstHash[:])
	secret := secondHash[:4]
	addb = append(addb, secret...)
	k.tronAddress = base58.Encode(addb)
	return nil
}

func (k *Key) TronAddress() string {
	return k.tronAddress
}

func (k *Key) newDashAddress() error {
	res2, err := hex.DecodeString(k.pubkey)
	if err != nil {
		return err
	}
	pubkey, err := btcec.ParsePubKey(res2)
	if err != nil {
		return err
	}
	pubKeyHash := dashbtcutil.Hash160(pubkey.SerializeCompressed())
	addr, err := dashbtcutil.NewAddressPubKeyHash(pubKeyHash,
		&chaincfgdash.MainNetParams)
	if err != nil {
		return err
	}
	k.dashAddress = addr.String()
	return nil
}

func (k *Key) DashAddress() string {
	return k.dashAddress
}

func (k *Key) newDogeAddress() error {
	res2, err := hex.DecodeString(k.pubkey)
	if err != nil {
		return err
	}
	pubkey, err := btcec.ParsePubKey(res2)
	if err != nil {
		return err
	}
	DOGEParams := chaincfg.MainNetParams
	DOGEParams.PubKeyHashAddrID = 0x1e // 30
	DOGEParams.ScriptHashAddrID = 0x16 // 22
	DOGEParams.PrivateKeyID = 0x9e     // 158

	pubKeyHash := dashbtcutil.Hash160(pubkey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash,
		&DOGEParams)
	if err != nil {
		fmt.Println(err)
		return err
	}
	k.dogeAddress = addr.String()
	return nil
}
func (k *Key) DogeAddress() string {
	return k.dogeAddress
}
