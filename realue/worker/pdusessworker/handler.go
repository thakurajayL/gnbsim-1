// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package pdusessworker

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"
    "os/exec"

	"github.com/omec-project/gnbsim/common"
	realuectx "github.com/omec-project/gnbsim/realue/context"
	"github.com/omec-project/gnbsim/util/test"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"log"
    "github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
"github.com/jamescun/tuntap"
	"encoding/binary"

)

const (
	ICMP_HEADER_LEN int = 8

	/*ipv4 package requires ipv4 header length in terms of number of bytes,
	  however it later converts it into number of 32 bit words
	*/
	IPV4_MIN_HEADER_LEN int = 20
)

func HandleInitEvent(pduSess *realuectx.PduSession,
	intfcMsg common.InterfaceMessage) (err error) {
	msg := intfcMsg.(*common.UeMessage)
	pduSess.WriteGnbChan = msg.CommChan
	pduSess.LastDataPktRecvd = false
	return nil
}

func SendIcmpEchoRequest(pduSess *realuectx.PduSession) (err error) {

	pduSess.Log.Traceln("Sending UL ICMP ping message")

	icmpPayload, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	if err != nil {
		pduSess.Log.Errorln("Failed to decode icmp hexString ")
		return
	}
	icmpPayloadLen := len(icmpPayload)
	pduSess.Log.Traceln("ICMP payload size:", icmpPayloadLen)

	ipv4hdr := ipv4.Header{
		Version:  4,
		Len:      IPV4_MIN_HEADER_LEN,
		Protocol: 1,
		Flags:    0,
		TotalLen: IPV4_MIN_HEADER_LEN + ICMP_HEADER_LEN + icmpPayloadLen,
		TTL:      64,
		Src:      pduSess.PduAddress,                   // ue IP address
		Dst:      net.ParseIP(pduSess.DefaultAs).To4(), // upstream router interface connected to Gi
		ID:       1,
	}
	checksum := test.CalculateIpv4HeaderChecksum(&ipv4hdr)
	ipv4hdr.Checksum = int(checksum)

	v4HdrBuf, err := ipv4hdr.Marshal()
	if err != nil {
		pduSess.Log.Errorln("ipv4hdr header marshal failed")
		return
	}

	icmpMsg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 12394, Seq: pduSess.GetNextSeqNum(),
			Data: icmpPayload,
		},
	}
	b, err := icmpMsg.Marshal(nil)
	if err != nil {
		pduSess.Log.Errorln("Failed to marshal icmp message")
		return
	}

	payload := append(v4HdrBuf, b...)

	userDataMsg := &common.UserDataMessage{}
	userDataMsg.Event = common.UL_UE_DATA_TRANSFER_EVENT
	userDataMsg.Payload = payload
	pduSess.WriteGnbChan <- userDataMsg
	pduSess.TxDataPktCount++

	pduSess.Log.Traceln("Sent UL ICMP ping message")

	return nil
}

func HandleIcmpMessage(pduSess *realuectx.PduSession,
	icmpPkt []byte) (err error) {
	icmpMsg, err := icmp.ParseMessage(1, icmpPkt)
	if err != nil {
		return fmt.Errorf("failed to parse icmp message:%v", err)
	}

	switch icmpMsg.Type {
	case ipv4.ICMPTypeEchoReply:
		echpReply := icmpMsg.Body.(*icmp.Echo)
		if echpReply == nil {
			return fmt.Errorf("icmp echo reply is nil")
		}

		pduSess.Log.Infof("Received ICMP Echo Reply, ID:%v, Seq:%v",
			echpReply.ID, echpReply.Seq)

		pduSess.RxDataPktCount++
		if pduSess.ReqDataPktInt == 0 {
			if pduSess.TxDataPktCount < pduSess.ReqDataPktCount {
				SendIcmpEchoRequest(pduSess)
			} else {
				msg := &common.UuMessage{}
				msg.Event = common.DATA_PKT_GEN_SUCCESS_EVENT
				pduSess.WriteUeChan <- msg
				pduSess.Log.Traceln("Sent Data Packet Generation Success Event")
			}
		}
	default:
		return fmt.Errorf("unsupported icmp message type:%v", icmpMsg.Type)
	}

	return nil
}

func HandleDlMessage(pduSess *realuectx.PduSession,
	msg common.InterfaceMessage) (err error) {

    if pduSess.ExtData == true {
        // write on interface 
        return
    }

	pduSess.Log.Traceln("Handling DL user data packet from gNb")
	if msg.GetEventType() == common.LAST_DATA_PKT_EVENT {
		pduSess.Log.Debugln("Received last downlink data packet")
		pduSess.LastDataPktRecvd = true
		return nil
	}

	dataMsg := msg.(*common.UserDataMessage)

	if dataMsg.Qfi != nil {
		pduSess.Log.Infoln("Received QFI value in downlink user data packet:", *dataMsg.Qfi)
	}

	ipv4Hdr, err := ipv4.ParseHeader(dataMsg.Payload)
	if err != nil {
		return fmt.Errorf("failed to parse ipv4 header:%v", err)
	}

	switch ipv4Hdr.Protocol {
	/* Currently supporting ICMP protocol */
	case 1:
		err = HandleIcmpMessage(pduSess, dataMsg.Payload[ipv4Hdr.Len:])
		if err != nil {
			return fmt.Errorf("failed to handle icmp message:%v", err)
		}
	default:
		return fmt.Errorf("unsupported ipv4 protocol:%v", ipv4Hdr.Protocol)
	}

	return nil
}

// entry point from app 
func HandleDataPktGenRequestEvent(pduSess *realuectx.PduSession,
	intfcMsg common.InterfaceMessage) (err error) {
    pduSess.ExtData = true
    // set pduSess.interDataMode = true/false
    if pduSess.ExtData == true {
        createTun(pduSess.PduAddress)
        return
    }
	cmd := intfcMsg.(*common.UeMessage)
	pduSess.ReqDataPktCount = cmd.UserDataPktCount
	pduSess.ReqDataPktInt = cmd.UserDataPktInterval
	pduSess.DefaultAs = cmd.DefaultAs
	if pduSess.ReqDataPktInt == 0 {
		err = SendIcmpEchoRequest(pduSess)
		if err != nil {
			return fmt.Errorf("failed to send icmp echo req:%v", err)
		}
	} else {
		go func(pduSess *realuectx.PduSession) error {
			for pduSess.TxDataPktCount < pduSess.ReqDataPktCount {
				err = SendIcmpEchoRequest(pduSess)
				if err != nil {
					return fmt.Errorf("failed to send icmp echo req:%v", err)
				}
				time.Sleep(time.Duration(pduSess.ReqDataPktInt) * time.Second)
			}
			msg := &common.UuMessage{}
			msg.Event = common.DATA_PKT_GEN_SUCCESS_EVENT
			pduSess.WriteUeChan <- msg
			pduSess.Log.Traceln("Sent Data Packet Generation Success Event")
			return nil
		}(pduSess)
	}
	return nil
}

func HandleConnectionReleaseRequestEvent(pduSess *realuectx.PduSession,
	intfcMsg common.InterfaceMessage) (err error) {

	userDataMsg := &common.UserDataMessage{}
	userDataMsg.Event = common.LAST_DATA_PKT_EVENT
	pduSess.WriteGnbChan <- userDataMsg
	// Releasing the reference so as to be freed by Garbage Collector
	pduSess.WriteGnbChan = nil
	return nil
}

func HandleQuitEvent(pduSess *realuectx.PduSession,
	intfcMsg common.InterfaceMessage) (err error) {

	if pduSess.WriteGnbChan != nil {
		userDataMsg := &common.UserDataMessage{}
		userDataMsg.Event = common.LAST_DATA_PKT_EVENT
		pduSess.WriteGnbChan <- userDataMsg
		pduSess.WriteGnbChan = nil
	}

	// Drain all the messages until END MARKER is received.
	// This ensures that the transmitting go routine is not blocked while
	// sending data on this channel
	if pduSess.LastDataPktRecvd != true {
		for pkt := range pduSess.ReadDlChan {
			if pkt.GetEventType() == common.LAST_DATA_PKT_EVENT {
				pduSess.Log.Debugln("Received last downlink data packet")
				break
			}
		}
	}

	pduSess.WriteUeChan = nil
	pduSess.Log.Infoln("Pdu Session terminated")

	return nil
}


func createTun( addr net.IP) {
	config := water.Config{
		DeviceType: water.TAP,
	}
	config.Name = "ue_0"

	ifce, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}
    arg0 := "ip"
    arg1 := "addr"
    arg2 := "add"
    arg3 := addr.String()
    arg33 := arg3 + "/24"
    arg4 := "dev"
    arg5 := "ue_0"

    cmd := exec.Command(arg0, arg1, arg2, arg33, arg4, arg5)
    _, err = cmd.Output()

    fmt.Println("Command1 ", cmd)
    if err != nil {
        fmt.Println(err.Error())
        return
    }

    arg0 = "ip"
    arg1 = "link"
    arg2 = "set"
    arg3 = "dev"
    arg4 = "ue_0"
    arg5 = "up"

    cmd = exec.Command(arg0, arg1, arg2, arg3, arg4, arg5)
    _, err = cmd.Output()

    fmt.Println("Command2 ", cmd)
    if err != nil {
        fmt.Println(err.Error())
        return
    }

	var frame ethernet.Frame
	for {
		frame.Resize(1500)
		n, err := ifce.Read([]byte(frame))
		if err != nil {
			log.Fatal(err)
		}
		frame = frame[:n]
		log.Printf("Dst: %s\n", frame.Destination())
		log.Printf("Src: %s\n", frame.Source())
		log.Printf("Ethertype: % x\n", frame.Ethertype())
		log.Printf("Payload: % x\n", frame.Payload())
	}
}
