// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package udprelay

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"go4.org/mem"
	"tailscale.com/disco"
	"tailscale.com/net/packet"
	"tailscale.com/types/key"
)

const (
	defaultBindLifetime        = time.Second * 5
	defaultSteadyStateLifetime = time.Minute * 5
)

// Server implements a UDP relay server.
type Server struct {
	// disco keypair used as part of 3-way bind handshake
	disco       key.DiscoPrivate
	discoPublic key.DiscoPublic

	// addrPorts contains the ip:port pairs returned as candidate server
	// endpoints in response to an allocation request.
	addrPorts []netip.AddrPort

	uc *net.UDPConn

	closeOnce sync.Once
	wg        sync.WaitGroup
	closed    bool

	mu      sync.Mutex // guards the following fields
	vniPool []uint32   // the pool of available VNIs
	byVNI   map[uint32]*serverEndpoint
	byDisco map[pairOfDiscoPubKeys]*serverEndpoint
}

// pairOfDiscoPubKeys is a pair of key.DiscoPublic. It must be constructed via
// newPairOfDiscoPubKeys to ensure lexicographical ordering.
type pairOfDiscoPubKeys [2]key.DiscoPublic

func (p pairOfDiscoPubKeys) String() string {
	return fmt.Sprintf("%s <=> %s", p[0].ShortString(), p[1].ShortString())
}

func newPairOfDiscoPubKeys(discoA, discoB key.DiscoPublic) pairOfDiscoPubKeys {
	var pair pairOfDiscoPubKeys
	cmp := discoA.Compare(discoB)
	if cmp == 1 {
		pair[0] = discoB
		pair[1] = discoA
	} else {
		pair[0] = discoA
		pair[1] = discoB
	}
	return pair
}

// ServerEndpoint contains the Server's endpoint details.
type ServerEndpoint struct {
	// ServerDisco is the Server's Disco public key used as part of the 3-way
	// bind handshake.
	ServerDisco key.DiscoPublic

	// AddrPorts are the IP:Port candidate pairs the Server may be reachable
	// over.
	AddrPorts []netip.AddrPort

	// VNI (Virtual Network Identifier) is the Geneve header VNI the Server
	// expects for associated packets.
	VNI uint32

	// BindLifetime is amount of time post-allocation the Server will keep the
	// endpoint alive while it has yet to be bound.
	BindLifetime time.Duration

	// SteadyStateLifetime is the amount of time post-bind the Server will keep
	// the endpoint alive lacking bidirectional data flow.
	SteadyStateLifetime time.Duration
}

type discoHandshakeState int

const (
	discoHandshakeStateInit discoHandshakeState = iota
	discoHandshakeBindSent
	discoHandshakeChallengeSent
	discoHandshakeAnswerSent
	discoHandshakeAnswerReceived
)

type serverEndpoint struct {
	discoPubKeys       pairOfDiscoPubKeys
	discoSharedSecrets [2]key.DiscoShared
	handeshakeState    [2]discoHandshakeState
	addrPorts          [2]netip.AddrPort
	lastSeen           [2]time.Time
	challenge          [2][disco.BindUDPEndpointChallengeLen]byte
	vni                uint32
	allocatedAt        time.Time
}

// bound returns true if both clients have completed their 3-way handshake,
// otherwise false.
func (e *serverEndpoint) bound() bool {
	return e.handeshakeState[0] == discoHandshakeAnswerReceived &&
		e.handeshakeState[1] == discoHandshakeAnswerReceived
}

// NewServer constructs a Server listening on port and returning addrs:port
// in response to allocation requests.
func NewServer(port uint16, addrs []netip.Addr) (*Server, error) {
	s := &Server{
		disco: key.NewDisco(),
	}
	s.discoPublic = s.disco.Public()
	addrPorts := make([]netip.AddrPort, 0, len(addrs))
	for _, addr := range addrs {
		addrPort, err := netip.ParseAddrPort(net.JoinHostPort(addr.String(), strconv.Itoa(int(port))))
		if err != nil {
			return nil, err
		}
		addrPorts = append(addrPorts, addrPort)
	}
	s.addrPorts = addrPorts
	// TODO: instead of allocating 10s of MBs for the full pool, allocate
	// smaller chunks and increase only if needed
	s.vniPool = make([]uint32, 0, 1<<24-1)
	for i := 1; i < 1<<24; i++ {
		s.vniPool = append(s.vniPool, uint32(i))
	}
	// TODO: this assumes multi-af socket capability, but we should probably
	// bind explicit ipv4 and ipv6 sockets.
	uc, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, err
	}
	s.uc = uc
	s.wg.Add(1)
	go s.packetReadLoop()
	return s, nil
}

// Close closes the server.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.uc.Close()
		s.wg.Wait()
		clear(s.byVNI)
		clear(s.byDisco)
		s.vniPool = nil
		s.closed = true
	})
	return nil
}

func (s *Server) handlePacket(from netip.AddrPort, b []byte) {
	gh := packet.GeneveHeader{}
	err := gh.Decode(b)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byVNI[gh.VNI]
	if !ok {
		// unknown VNI
		return
	}

	if !gh.Control {
		if !e.bound() {
			// not a control packet, but serverEndpoint isn't bound
			return
		}
		var to netip.AddrPort
		switch {
		case from == e.addrPorts[0]:
			to = e.addrPorts[1]
		case from == e.addrPorts[1]:
			to = e.addrPorts[0]
		default:
			// unrecognized source
			return
		}
		// relay packet
		s.uc.WriteMsgUDPAddrPort(b, nil, to)
		return
	}

	if e.bound() {
		// control packet, but serverEndpoint is already bound
		return
	}

	if gh.Protocol != packet.GeneveProtocolDisco {
		// control packet, but not Disco
		return
	}

	msg := b[packet.GeneveFixedHeaderLength:]
	senderRaw, isDiscoMsg := disco.Source(msg)
	if !isDiscoMsg {
		// Geneve header protocol field indicated it was Disco, but it's not
		return
	}
	sender := key.DiscoPublicFromRaw32(mem.B(senderRaw))
	senderIndex := -1
	switch {
	case sender.Compare(e.discoPubKeys[0]) == 0:
		senderIndex = 0
	case sender.Compare(e.discoPubKeys[1]) == 0:
		senderIndex = 1
	default:
		// unknown Disco public key
		return
	}

	const headerLen = len(disco.Magic) + key.DiscoPublicRawLen
	discoPayload, ok := e.discoSharedSecrets[senderIndex].Open(msg[headerLen:])
	if !ok {
		// unable to decrypt the disco payload
		return
	}

	discoMsg, err := disco.Parse(discoPayload)
	if err != nil {
		// unable to parse the disco payload
	}

	handshakeState := e.handeshakeState[senderIndex]
	if handshakeState == discoHandshakeAnswerReceived {
		// this sender is already bound
		return
	}
	switch discoMsg := discoMsg.(type) {
	case *disco.BindUDPEndpoint:
		switch handshakeState {
		case discoHandshakeStateInit:
			// generate a challenge, maybe we should do this at allocation time?
			rand.Read(e.challenge[senderIndex][:])
			// set sender addr
			e.addrPorts[senderIndex] = from
			fallthrough
		case discoHandshakeChallengeSent:
			if from != e.addrPorts[senderIndex] {
				// this is a later arriving bind from a different source, discard
				return
			}
			m := new(disco.BindUDPEndpointChallenge)
			copy(m.Challenge[:], e.challenge[senderIndex][:])
			reply := make([]byte, packet.GeneveFixedHeaderLength, 512)
			err = gh.Encode(reply)
			if err != nil {
				return
			}
			reply = append(reply, disco.Magic...)
			reply = s.discoPublic.AppendTo(reply)
			box := e.discoSharedSecrets[senderIndex].Seal(m.AppendMarshal(nil))
			reply = append(reply, box...)
			s.uc.WriteMsgUDPAddrPort(reply, nil, from)
			// set new state
			e.handeshakeState[senderIndex] = discoHandshakeChallengeSent
			return
		default:
			// disco.BindUDPEndpoint is unexpected in all other handshake states
			return
		}
	case *disco.BindUDPEndpointAnswer:
		switch handshakeState {
		case discoHandshakeChallengeSent:
			if from != e.addrPorts[senderIndex] {
				// sender source has changed
				return
			}
			if !bytes.Equal(discoMsg.Answer[:], e.challenge[senderIndex][:]) {
				// bad answer
				return
			}
			// sender is now bound
			e.handeshakeState[senderIndex] = discoHandshakeAnswerReceived
			// record last seen as bound time
			e.lastSeen[senderIndex] = time.Now()
			return
		default:
			// disco.BindUDPEndpointAnswer is unexpected in all other handshake
			// states, or we've already handled it
			return
		}
	default:
		// unexpected Disco message type
		return
	}
}

func (s *Server) packetReadLoop() {
	defer func() {
		s.wg.Done()
		s.Close()
	}()
	b := make([]byte, 1<<16-1)
	for {
		n, from, err := s.uc.ReadFromUDPAddrPort(b)
		if err != nil {
			return
		}
		s.handlePacket(from, b[:n])
	}
}

var ErrServerClosed = errors.New("server closed")

// AllocateEndpoint allocates a ServerEndpoint for the provided pair of
// key.DiscoPublic's. It returns ErrServerClosed if the server has been closed.
func (s *Server) AllocateEndpoint(discoA, discoB key.DiscoPublic) (ServerEndpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ServerEndpoint{}, ErrServerClosed
	}

	pair := newPairOfDiscoPubKeys(discoA, discoB)
	e, ok := s.byDisco[pair]
	if ok {
		if !e.bound() {
			// If the endpoint is not yet bound this is likely an allocation
			// race between two clients utilizing the same relay. Instead of
			// re-allocating we return the existing allocation state, and reset
			// the allocation time.
			e.allocatedAt = time.Now()
			return ServerEndpoint{
				ServerDisco:         s.discoPublic,
				AddrPorts:           s.addrPorts,
				VNI:                 e.vni,
				BindLifetime:        defaultBindLifetime,
				SteadyStateLifetime: defaultSteadyStateLifetime,
			}, nil
		}
		// If an endpoint exists for the pair of key.DiscoPublic's, and is
		// already bound, delete it. We will re-allocate a new endpoint. Chances
		// are clients cannot make use of the existing, bound allocation if
		// they are requesting a new one.
		delete(s.byDisco, pair)
		delete(s.byVNI, e.vni)
		s.vniPool = append(s.vniPool, e.vni)
	}

	if len(s.vniPool) == 0 {
		return ServerEndpoint{}, errors.New("VNI pool exhausted")
	}

	e = &serverEndpoint{
		discoPubKeys: pair,
		allocatedAt:  time.Now(),
	}
	e.discoSharedSecrets[0] = s.disco.Shared(e.discoPubKeys[0])
	e.discoSharedSecrets[1] = s.disco.Shared(e.discoPubKeys[1])
	e.vni, s.vniPool = s.vniPool[len(s.vniPool)-1], s.vniPool[:len(s.vniPool)-1]
	s.byDisco[pair] = e
	s.byVNI[e.vni] = e

	return ServerEndpoint{
		AddrPorts:           s.addrPorts,
		VNI:                 e.vni,
		BindLifetime:        defaultBindLifetime,
		SteadyStateLifetime: defaultSteadyStateLifetime,
	}, nil
}
