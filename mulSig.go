package main

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
)

// GenerateRandomNum 产生随机数r
func GenerateRandomNum(s schnorr.Suite) kyber.Scalar {
	var g kyber.Group = s
	return g.Scalar().Pick(s.RandomStream())
}

func Hash(g kyber.Group, publicKey, R kyber.Point, msg []byte) (kyber.Scalar, error) {
	h := sha512.New()
	if _, err := R.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := publicKey.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := h.Write(msg); err != nil {
		return nil, err
	}
	return g.Scalar().SetBytes(h.Sum(nil)), nil
}

// MySign 在各节点事先共享R_i=r_i*G并聚合得到aggregatedR后，对消息进行签名得到<R,s_i>
func MySign(s schnorr.Suite, privateKey kyber.Scalar, msg []byte, r kyber.Scalar, aggregatedR, aggregatedPublicKey kyber.Point) ([]byte, error) {
	var g kyber.Group = s

	// 普通schnorr签名使用自己生成的随机数r_i与G相乘得到R_i,如注释代码所示，此函数中使用聚合的R=SUM(R_i)
	// r := g.Scalar().Pick(s.RandomStream())
	// R := g.Point().Mul(r, nil)

	// 计算hash(aggregatedPublicKey||aggregatedR||msg)
	h, err := Hash(g, aggregatedPublicKey, aggregatedR, msg)
	if err != nil {
		panic(err)
	}

	// 计算签名s_i = r_i + hash*privateKey
	xh := g.Scalar().Mul(privateKey, h)
	s_i := g.Scalar().Add(r, xh)

	var b bytes.Buffer
	if _, err := aggregatedR.MarshalTo(&b); err != nil {
		return nil, err
	}
	if _, err := s_i.MarshalTo(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil

}

func Verify(g kyber.Group, aggregatedPublicKey, msg, sig []byte) error {
	aggregatedR := g.Point()
	aggregatedS := g.Scalar()
	pointSize := aggregatedR.MarshalSize()
	scalarSize := aggregatedS.MarshalSize()
	sigSize := pointSize + scalarSize
	// 检查签名长度
	if len(sig) != sigSize {
		return fmt.Errorf("schnorr: signature of invalid length %d instead of %d", len(sig), sigSize)
	}
	// 从签名中分离出aggregatedR和aggregatedS
	if err := aggregatedR.UnmarshalBinary(sig[:pointSize]); err != nil {
		return err
	}
	if err := aggregatedS.UnmarshalBinary(sig[pointSize:]); err != nil {
		return err
	}

	aggregatedPublicKey1 := g.Point()
	err := aggregatedPublicKey1.UnmarshalBinary(aggregatedPublicKey)
	if err != nil {
		return fmt.Errorf("schnorr: error unMarshalling public key")
	}

	// 计算hash(aggregatedPublicKey, aggregatedR, msg)
	h, err := Hash(g, aggregatedPublicKey1, aggregatedR, msg)
	if err != nil {
		return err
	}

	// 计算s*G
	sG := g.Point().Mul(aggregatedS, nil)
	// 计算aggregatedR + hash*aggregatedPublicKey
	hAp := g.Point().Mul(h, aggregatedPublicKey1)
	aRhAp := g.Point().Add(aggregatedR, hAp)

	if !sG.Equal(aRhAp) {
		return errors.New("schnorr: signature verify failed")
	}
	return nil
}

// getAggregatedPublicKey 计算聚合公钥
func GetAggregatedPublicKey(g kyber.Group, publicKey1, publicKey2 []byte) (kyber.Point, error) {

	pk1, pk2 := g.Point(), g.Point()
	if err := pk1.UnmarshalBinary(publicKey1); err != nil {
		return nil, err
	}
	if err := pk2.UnmarshalBinary(publicKey2); err != nil {
		return nil, err
	}
	rst := g.Point().Add(pk1, pk2)

	return rst, nil
}

// getAggregatedR 计算聚合R
func GetAggregatedR(g kyber.Group, R1, R2 []byte) (kyber.Point, error) {
	R11, R22 := g.Point(), g.Point()
	if err := R11.UnmarshalBinary(R1); err != nil {
		return nil, err
	}
	if err := R22.UnmarshalBinary(R2); err != nil {
		return nil, err
	}
	rst := g.Point().Add(R11, R22)

	return rst, nil
}

// getAggregatedR 计算聚合s
func GetAggregatedS(g kyber.Group, s1, s2 []byte) (kyber.Scalar, error) {
	s11, s22 := g.Scalar(), g.Scalar()
	if err := s11.UnmarshalBinary(s1); err != nil {
		return nil, err
	}
	if err := s22.UnmarshalBinary(s2); err != nil {
		return nil, err
	}
	rst := g.Scalar().Add(s11, s22)

	return rst, nil
}

// pointToBytes Marshal kyber.Point to []byte
func PointToBytes(point kyber.Point) ([]byte, error) {
	var rst bytes.Buffer
	if _, err := point.MarshalTo(&rst); err != nil {
		return nil, err
	}
	return rst.Bytes(), nil
}

// DivideSi leader从收到的各个子节点签名中分离出s_i
func DivideSi(g kyber.Group, sig []byte) kyber.Scalar {
	R := g.Point()
	s := g.Scalar()
	pointSize := R.MarshalSize()

	// 从签名中分离出s_i
	if err := s.UnmarshalBinary(sig[pointSize:]); err != nil {
		panic(err)
	}
	return s
}
