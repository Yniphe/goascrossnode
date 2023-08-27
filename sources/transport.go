package main

import (
	"context"
	"crypto/sha256"
	tls "github.com/refraction-networking/utls"
	"net"
	"net/http"
	"strconv"
	"strings"
)

func Transport(ja3 string, config *tls.Config) (*http.Transport, error) {

	//spec, err := DecodeJA3(ja3)
	//if err != nil {
	//	return nil, err
	//}

	dials := func(ctx context.Context, network, addr string) (net.Conn, error) {
		//if err != nil {
		//	return nil, err
		//}

		config.ServerName = strings.Split(addr, ":")[0]

		//if err != nil {
		//	return nil, err
		//}

		conn, err := net.Dial(network, addr)

		if err != nil {
			return nil, err
		}

		uTLSConn := tls.UClient(conn, config, tls.HelloIOS_14)
		//if err := uTLSConn.ApplyPreset(spec); err != nil {
		//	return nil, err
		//}

		if err := uTLSConn.Handshake(); err != nil {
			return nil, err
		}

		return uTLSConn, nil
	}

	return &http.Transport{DialTLSContext: dials}, nil
}

func DecodeJA3(ja3 string) (*tls.ClientHelloSpec, error) {
	extMap := generateMap()
	tokens := strings.Split(ja3, ",")

	//version := tokens[0]
	ciphers := strings.Split(tokens[1], "-")
	extensions := strings.Split(tokens[2], "-")
	curves := strings.Split(tokens[3], "-")
	if len(curves) == 1 && curves[0] == "" {
		curves = []string{}
	}
	pointFormats := strings.Split(tokens[4], "-")
	if len(pointFormats) == 1 && pointFormats[0] == "" {
		pointFormats = []string{}
	}
	var targetCurves []tls.CurveID
	targetCurves = append(targetCurves, tls.CurveID(tls.GREASE_PLACEHOLDER)) //append grease for Chrome browsers
	for _, c := range curves {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		targetCurves = append(targetCurves, tls.CurveID(cid))
	}
	extMap["10"] = &tls.SupportedCurvesExtension{Curves: targetCurves}

	var targetPointFormats []byte
	for _, p := range pointFormats {
		pid, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, err
		}
		targetPointFormats = append(targetPointFormats, byte(pid))
	}
	extMap["11"] = &tls.SupportedPointsExtension{SupportedPoints: targetPointFormats}

	// пока не используется
	// vid64, err := strconv.ParseUint(version, 10, 16)
	// if err != nil {
	//	return nil, err
	// }
	// vid := uint16(vid64)
	extMap["43"] = &tls.SupportedVersionsExtension{
		Versions: []uint16{
			tls.VersionTLS12,
		},
	}

	var extensionsArray []tls.TLSExtension
	for _, e := range extensions {
		te, ok := extMap[e]
		if !ok {
			continue
		}

		extensionsArray = append(extensionsArray, te)
	}

	var suites []uint16
	for _, c := range ciphers {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		suites = append(suites, uint16(cid))
	}

	return &tls.ClientHelloSpec{
		TLSVersMin:         tls.VersionTLS11,
		TLSVersMax:         tls.VersionTLS13,
		CipherSuites:       suites,
		CompressionMethods: []byte{0},
		Extensions:         extensionsArray,
		GetSessionID:       sha256.Sum256,
	}, nil
}

func generateMap() (extMap map[string]tls.TLSExtension) {
	extMap = map[string]tls.TLSExtension{
		"0":  &tls.SNIExtension{},
		"5":  &tls.StatusRequestExtension{},
		"10": &tls.SupportedCurvesExtension{},
		"11": &tls.SupportedPointsExtension{},
		"13": &tls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithSHA1,
				tls.PKCS1WithSHA1,
			},
		},
		"16": &tls.ALPNExtension{
			AlpnProtocols: []string{"http/1.1"},
		},
		"17": &tls.GenericExtension{Id: 17},
		"18": &tls.SCTExtension{},
		"21": &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		"22": &tls.GenericExtension{Id: 22},
		"23": &tls.ExtendedMasterSecretExtension{},
		"27": &tls.UtlsCompressCertExtension{
			Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli},
		},
		"28": &tls.FakeRecordSizeLimitExtension{},
		"35": &tls.SessionTicketExtension{},
		"34": &tls.GenericExtension{Id: 34},
		"41": &tls.GenericExtension{Id: 41},
		"43": &tls.SupportedVersionsExtension{Versions: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.VersionTLS13,
			tls.VersionTLS12,
			tls.VersionTLS11,
			tls.VersionTLS10}},
		"44": &tls.CookieExtension{},
		"45": &tls.PSKKeyExchangeModesExtension{Modes: []uint8{
			tls.PskModeDHE,
		}},
		"49": &tls.GenericExtension{Id: 49},
		"50": &tls.GenericExtension{Id: 50},
		"51": &tls.KeyShareExtension{KeyShares: []tls.KeyShare{
			{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
			{Group: tls.X25519},
		}},
		"30032": &tls.GenericExtension{Id: 0x7550, Data: []byte{0}}, // FIXME: this is a hack to make the extension work
		"13172": &tls.NPNExtension{},
		"17513": &tls.ApplicationSettingsExtension{
			SupportedProtocols: []string{
				//"h2",
				"http/1.1",
			},
		},
		"65281": &tls.RenegotiationInfoExtension{
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
	}
	return

}
