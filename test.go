package main

import (
	"bytes"
	"fmt"

	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/kyber/v3/util/key"
)

func main() {

	// s, _ := schnorr.Sign(suite, kp.Private, msg) // 签名，返回的是Marshal(R||s)
	// fmt.Println(s)
	// suite1 := edwards25519.NewBlakeSHA256Ed25519()
	// kp := key.NewKeyPair(suite)
	// s1, _ := schnorr.Sign(suite, kp.Private, msg)
	// _ = schnorr.Verify(suite, kp.Public, msg, s)

	msg := []byte("Hello Schnorr")
	suite := edwards25519.NewBlakeSHA256Ed25519() // 创建曲线
	// 节点1生成密钥对及随机数，并计算R1
	kp1 := key.NewKeyPair(suite) // 产生密钥对
	r1 := GenerateRandomNum(suite)
	R1 := suite.Point().Mul(r1, nil)
	R1Bytes, err := PointToBytes(R1)
	if err != nil {
		panic(err)
	}
	pk1Bytes, err := PointToBytes(kp1.Public)
	if err != nil {
		panic(err)
	}

	// 节点2生成密钥对及随机数，并计算R2
	kp2 := key.NewKeyPair(suite) // 产生密钥对
	r2 := GenerateRandomNum(suite)
	R2 := suite.Point().Mul(r2, nil)
	R2Bytes, err := PointToBytes(R2)
	if err != nil {
		panic(err)
	}
	pk2Bytes, err := PointToBytes(kp2.Public)
	if err != nil {
		panic(err)
	}

	// 聚合R和聚合公钥
	aggregatedR, err := GetAggregatedR(suite, R1Bytes, R2Bytes)
	if err != nil {
		panic(err)
	}
	aggregatedPubKey, err := GetAggregatedPublicKey(suite, pk1Bytes, pk2Bytes)
	if err != nil {
		panic(err)
	}

	// 计算各自的sig_i=<aggregatedR, s_i>
	sig1, err := MySign(suite, kp1.Private, msg, r1, aggregatedR, aggregatedPubKey)
	if err != nil {
		panic(err)
	}
	sig2, err := MySign(suite, kp2.Private, msg, r2, aggregatedR, aggregatedPubKey)
	if err != nil {
		panic(err)
	}

	// 分离出s_i来，然后聚合得到aggregatedS
	aaa := suite.Point()
	aggregatedS1 := suite.Scalar()
	aggregatedS2 := suite.Scalar()
	pointSize := aaa.MarshalSize()
	// scalarSize := bbb.MarshalSize()
	if err := aggregatedS1.UnmarshalBinary(sig1[pointSize:]); err != nil {
		panic(err)
	}
	if err := aggregatedS2.UnmarshalBinary(sig2[pointSize:]); err != nil {
		panic(err)
	}

	aggregatedS := suite.Scalar().Add(aggregatedS1, aggregatedS2)

	var aggregatedSig bytes.Buffer
	if _, err := aggregatedR.MarshalTo(&aggregatedSig); err != nil {
		panic(err)
	}
	if _, err := aggregatedS.MarshalTo(&aggregatedSig); err != nil {
		panic(err)
	}

	// verify
	err = schnorr.Verify(suite, aggregatedPubKey, msg, aggregatedSig.Bytes())
	if err == nil {
		fmt.Println("SUCCESS!")
	}

}
