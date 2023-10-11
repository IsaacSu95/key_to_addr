package key_to_addr

//
//import (
//	"crypto/ecdsa"
//	"encoding/hex"
//	"errors"
//	"fmt"
//	"log"
//
//	"github.com/btcsuite/btcd/btcec"
//	"github.com/btcsuite/btcd/chaincfg"
//	"github.com/btcsuite/btcd/txscript"
//	"github.com/btcsuite/btcutil"
//	dashbtcutil "github.com/dashpay/dashd-go/btcutil"
//	chaincfgdash "github.com/dashpay/dashd-go/chaincfg"
//	"github.com/ethereum/go-ethereum/accounts"
//	"github.com/ethereum/go-ethereum/common/hexutil"
//	"github.com/ethereum/go-ethereum/crypto"
//	addr "github.com/fbsobreira/gotron-sdk/pkg/address"
//	"github.com/gcash/bchd/bchec"
//	chaincfgbch "github.com/gcash/bchd/chaincfg"
//	"github.com/gcash/bchutil"
//)
//
//var (
//	bigRadix = big.NewInt(58)
//	bigZero  = big.NewInt(0)
//)

//const (
//	ALPHABET           = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
//	walletVersion      = byte(0x00)
//	addressChecksumLen = 4
//)
//// Account represents an Ethereum account located at a specific location defined
//// by the optional URL field.
//type Account struct {
//	Private *ecdsa.PrivateKey `json:"address"`
//	URL     accounts.URL      `json:"url"` // Optional resource locator within a backend
//}
//
//type Address struct {
//	Address  string
//	Pubkey   string
//	CoinType string
//}
//
//// SignHash implements accounts.Wallet, which allows signing arbitrary data.
//func (acc *Account) SignHash(hash []byte, pubkey string) ([]byte, error) {
//
//	cointype := GetCoinTypeFromPath(acc.URL.Path)
//	switch cointype {
//	case CoinTypeBTC, CoinTypeDASH:
//		key := (*btcec.PrivateKey)(acc.Private)
//		a, err := key.Sign(hash)
//		return a.Serialize(), err
//	case CoinTypeBCH:
//		key := (*bchec.PrivateKey)(acc.Private)
//		sig, err := key.SignSchnorr(hash)
//		return sig.Serialize(), err
//	case CoinTypeDoge:
//		sign, err := acc.dogeSign(hash, pubkey)
//		return []byte(sign), err
//
//	//case CoinTypeDASH:
//	//key := (*btcec.PrivateKey)(acc.Private)
//	//sig:= dashecdsa.Sign(key, hash)
//
//	default:
//		log.Println(acc.Address())
//		fmt.Println(acc.URL)
//		return crypto.Sign(hash, acc.Getprivkey())
//	}
//	return nil, nil
//}
//
//func GenerateKey() (wif string, address string) {
//	priv, err := btcec.NewPrivateKey(btcec.S256())
//	if err != nil {
//		return "", ""
//	}
//	if len(priv.D.Bytes()) != 32 {
//		for {
//			priv, err := btcec.NewPrivateKey(btcec.S256())
//			if err != nil {
//				continue
//			}
//			if len(priv.D.Bytes()) == 32 {
//				break
//			}
//		}
//	}
//	a := addr.PubkeyToAddress(priv.ToECDSA().PublicKey)
//	address = a.String()
//	wif = hex.EncodeToString(priv.D.Bytes())
//	return
//}
//func (acc *Account) Address() (Address, error) {
//	cointype := GetCoinTypeFromPath(acc.URL.Path)
//	switch cointype {
//	case CoinTypeBTC:
//		return acc.btcAddress()
//	case CoinTypeBCH:
//		return acc.bchAddress()
//	case CoinTypeDoge:
//		return acc.DogeAddress()
//	case CoinTypeDASH:
//		return acc.dashAddress()
//	case CoinTypeETH, CoinTypeMATIC, CoinTypeBSC, CoinTypeFTM, CoinTypeAVAXC, CoinTypeOPMAINNET:
//		fmt.Println(acc.ethAddress())
//		fmt.Println(acc.URL)
//		return acc.ethAddress()
//	case CoinTypeTRON:
//		return acc.tronAddress()
//	default:
//		return Address{}, errors.New("Unsupport CoinType")
//	}
//}
//
//func (acc *Account) btcAddress() (Address, error) {
//	pubkey := btcec.PublicKey(acc.Private.PublicKey)
//	pkHash := btcutil.Hash160(pubkey.SerializeCompressed())
//
//	hash, err := btcutil.NewAddressPubKeyHash(pkHash, &chaincfg.MainNetParams)
//	if err != nil {
//		return Address{}, err
//	}
//	addr := hash.EncodeAddress()
//	pk := (*btcec.PublicKey)(&acc.Private.PublicKey)
//	oub := pk.SerializeUncompressed()
//
//	btcwif, err := btcutil.NewWIF((*btcec.PrivateKey)(acc.Private), &chaincfg.MainNetParams, true)
//	serializedPubKey := btcwif.SerializePubKey()
//	// generate a normal p2wkh address from the pubkey hash
//	witnessProg := btcutil.Hash160(serializedPubKey)
//	addressWitnessPubKeyHash, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, &chaincfg.MainNetParams)
//	if err != nil {
//		return Address{}, err
//	}
//	segwitBech32 := addressWitnessPubKeyHash.EncodeAddress()
//
//	// generate an address which is
//	// backwards compatible to Bitcoin nodes running 0.6.0 onwards, but
//	// allows us to take advantage of segwit's scripting improvments,
//	// and malleability fixes.
//	serializedScript, err := txscript.PayToAddrScript(addressWitnessPubKeyHash)
//	if err != nil {
//		return Address{}, err
//	}
//	addressScriptHash, err := btcutil.NewAddressScriptHash(serializedScript, &chaincfg.MainNetParams)
//	if err != nil {
//		return Address{}, err
//	}
//	segwitNested := addressScriptHash.EncodeAddress()
//
//	fmt.Println(addr, segwitBech32, segwitNested)
//	//fmt.Println("pubkey", hex.EncodeToString(oub))
//	return Address{Address: segwitNested, CoinType: CoinTypeMap[CoinTypeBTC], Pubkey: hex.EncodeToString(oub)}, nil
//}
//
//func (acc *Account) DogeAddress() (Address, error) {
//	//pubkey := btcec.PublicKey(acc.Private.PublicKey)
//	//pkHash := btcutil.Hash160(pubkey.SerializeCompressed())
//	//
//	//hash, err := btcutil.NewAddressPubKeyHash(pkHash, &chaincfg.MainNetParams)
//	//if err != nil {
//	//	return Address{}, err
//	//}
//	//addr := hash.EncodeAddress()
//	//pk := (*btcec.PublicKey)(&acc.Private.PublicKey)
//	//oub := pk.SerializeUncompressed()
//
//	DOGEParams := chaincfg.MainNetParams
//	DOGEParams.PubKeyHashAddrID = 0x1e // 30
//	DOGEParams.ScriptHashAddrID = 0x16 // 22
//	DOGEParams.PrivateKeyID = 0x9e     // 158
//
//	pubkey := btcec.PublicKey(acc.Private.PublicKey)
//	pubKeyHash := dashbtcutil.Hash160(pubkey.SerializeCompressed())
//	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash,
//		&DOGEParams)
//	if err != nil {
//		fmt.Println(err)
//		return Address{}, err
//	}
//
//	return Address{
//		Address:  addr.String(),
//		Pubkey:   hex.EncodeToString(pubkey.SerializeUncompressed()),
//		CoinType: CoinTypeMap[CoinTypeDoge],
//	}, nil
//
//}
//
//func (acc *Account) bchAddress() (Address, error) {
//	pubkey := btcec.PublicKey(acc.Private.PublicKey)
//	pubKeyHash := bchutil.Hash160(pubkey.SerializeCompressed())
//	addr, err := bchutil.NewAddressPubKeyHash(pubKeyHash,
//		&chaincfgbch.MainNetParams)
//	if err != nil {
//		fmt.Println(err)
//		return Address{}, err
//	}
//	return Address{
//		Address:  addr.String(),
//		Pubkey:   hex.EncodeToString(pubkey.SerializeUncompressed()),
//		CoinType: "bch",
//	}, nil
//}
//
//func (acc *Account) ethAddress() (Address, error) {
//	return Address{Address: crypto.PubkeyToAddress(acc.Private.PublicKey).Hex(), CoinType: CoinTypeMap[CoinTypeETH]}, nil
//}
//
//func (acc *Account) tronAddress() (Address, error) {
//	return Address{Address: addr.PubkeyToAddress(acc.Private.PublicKey).String(), CoinType: CoinTypeMap[CoinTypeTRON]}, nil
//}
//func (acc *Account) dashAddress() (Address, error) {
//	pubkey := btcec.PublicKey(acc.Private.PublicKey)
//	pubKeyHash := dashbtcutil.Hash160(pubkey.SerializeCompressed())
//	addr, err := dashbtcutil.NewAddressPubKeyHash(pubKeyHash,
//		&chaincfgdash.MainNetParams)
//	if err != nil {
//		fmt.Println(err)
//		return Address{}, err
//	}
//
//	return Address{
//		Address:  addr.String(),
//		Pubkey:   hex.EncodeToString(pubkey.SerializeUncompressed()),
//		CoinType: "dash",
//	}, nil
//}
//
//func (acc *Account) gethexprivkey() string {
//	pbytes := crypto.FromECDSA(acc.Private)
//	s := hexutil.Encode(pbytes)[2:]
//	return s
//}
//
//func (acc *Account) Getprivkey() *ecdsa.PrivateKey {
//	pbytes := crypto.FromECDSA(acc.Private)
//	s := hexutil.Encode(pbytes)[2:]
//	privateKey, err := crypto.HexToECDSA(s)
//	if err != nil {
//		log.Fatal(err)
//	}
//	return privateKey
//
//}
//
//func (acc *Account) dogeSign(txHex []byte, scriptkey string) (signedTx string, err error) {
//	fmt.Println("unSignedRaw:", string(txHex))
//	index := libdogecoin.W_store_raw_transaction(string(txHex))
//	defer libdogecoin.W_clear_transaction(index)
//	//addr: DENtHrZyfTEY5VLiZkiHp5xQK8CG1eAo4c
//	libdogecoin.W_context_start()
//	DOGEParams := chaincfg.MainNetParams
//	DOGEParams.PubKeyHashAddrID = 0x1e // 30
//	DOGEParams.ScriptHashAddrID = 0x16 // 22
//	DOGEParams.PrivateKeyID = 0x9e     // 158
//	btcwif, err := btcutil.NewWIF((*btcec.PrivateKey)(acc.Private), &DOGEParams, true)
//
//	privstring := btcwif.String()
//	defer libdogecoin.W_context_stop()
//	if libdogecoin.W_sign_transaction(index, scriptkey, privstring) != 1 {
//		return "", fmt.Errorf("libdogecoin failed to sign transaction")
//	}
//	signedTx = libdogecoin.W_get_raw_transaction(index)
//	if signedTx == "" {
//		return "", fmt.Errorf("signedTx is nil")
//	}
//	fmt.Println("signedRaw:", signedTx)
//	return signedTx, nil
//}
//
////func SignatureScript(tx *wire.MsgTx, idx int, subscript []byte, hashType SigHashType, privKey *btcec.PrivateKey, compress bool) ([]byte, error) {
////	sig, err := dashtxscript.RawTxInSignature(tx, idx, subscript, hashType, privKey)
////	if err != nil {
////		return nil, err
////	}
////
////	pk := (*btcec.PublicKey)(&privKey.PublicKey)
////	var pkData []byte
////	if compress {
////		pkData = pk.SerializeCompressed()
////	} else {
////		pkData = pk.SerializeUncompressed()
////	}
////
////	return NewScriptBuilder().AddData(sig).AddData(pkData).Script()
////}
//	func EncodeAddress(hash160 []byte, key byte) string {
//		tosum := make([]byte, 21)
//		tosum[0] = key
//		copy(tosum[1:], hash160)
//		cksum := doubleHash(tosum)
//
//		// Address before base58 encoding is 1 byte for netID, ripemd160 hash
//		// size, plus 4 bytes of checksum (total 25).
//		b := make([]byte, 25)
//		b[0] = key
//		copy(b[1:], hash160)
//		copy(b[21:], cksum[:4])
//
//		return base58Encode(b)
//	}
//
//	func hash160(data []byte) []byte {
//		if len(data) == 1 && data[0] == 0 {
//			data = []byte{}
//		}
//		h1 := sha256.Sum256(data)
//		h2 := ripemd160.New()
//		h2.Write(h1[:])
//		return h2.Sum(nil)
//	}
//
//	func doubleHash(data []byte) []byte {
//		h1 := sha256.Sum256(data)
//		h2 := sha256.Sum256(h1[:])
//		return h2[:]
//	}
//
// // Base58Encode encodes a byte slice to a modified base58 string.
//
//	func base58Encode(b []byte) string {
//		x := new(big.Int)
//		x.SetBytes(b)
//
//		answer := make([]byte, 0)
//		for x.Cmp(bigZero) > 0 {
//			mod := new(big.Int)
//			x.DivMod(x, bigRadix, mod)
//			answer = append(answer, ALPHABET[mod.Int64()])
//		}
//
//		// leading zero bytes
//		for _, i := range b {
//			if i != 0 {
//				break
//			}
//			answer = append(answer, ALPHABET[0])
//		}
//
//		// reverse
//		alen := len(answer)
//		for i := 0; i < alen/2; i++ {
//			answer[i], answer[alen-1-i] = answer[alen-1-i], answer[i]
//		}
//
//		return string(answer)
//	}
