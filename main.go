package main

import (
	"fmt"
	"time"

	"github.com/ElrondNetwork/elrond-go/crypto"

	"github.com/ElrondNetwork/elrond-go/crypto/signing"
	"github.com/ElrondNetwork/elrond-go/crypto/signing/mcl"
	"github.com/ElrondNetwork/elrond-go/crypto/signing/mcl/multisig"
	multisig2 "github.com/ElrondNetwork/elrond-go/crypto/signing/multisig"
	"github.com/ElrondNetwork/elrond-go/hashing/blake2b"
)

func main() {
	suite := mcl.NewSuiteBLS12()
	kg := signing.NewKeyGenerator(suite)

	hasher, err := blake2b.NewBlake2bWithSize(multisig2.BlsHashSize)

	message := []byte("abc")

	llSigner := &multisig.BlsMultiSigner{Hasher: hasher}
	nbSigs := uint16(50)
	pubKeys := make([]crypto.PublicKey, nbSigs)
	sigShares := make([][]byte, nbSigs)
	for i := uint16(0); i < nbSigs; i++ {
		sk, pk := kg.GeneratePair()
		pubKeys[i] = pk
		sigShares[i], _ = llSigner.SignShare(sk, message)
		t0 := time.Now()
		llSigner.VerifySigShare(pk, message, sigShares[i])
		fmt.Println("VerifySigShare took", time.Now().Sub(t0), "sig len", len(sigShares[i]))
	}

	t1 := time.Now()
	aggSig, err := llSigner.AggregateSignatures(suite, sigShares, pubKeys)
	if err != nil {
		panic(err)
	}

	t2 := time.Now()
	err = llSigner.VerifyAggregatedSig(suite, pubKeys, aggSig, message)
	if err != nil {
		panic(err)
	}

	t3 := time.Now()
	fmt.Println("pass, step1 took", t2.Sub(t1), "step2 took", t3.Sub(t2), "aggSig len", len(aggSig))
}
