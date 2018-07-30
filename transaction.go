/*
Copyright: Cognition Foundry. All Rights Reserved.
License: Apache License Version 2.0
*/
package gohfc

import (
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/msp"
	"encoding/pem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/golang/protobuf/ptypes"
	"time"
	"github.com/hyperledger/fabric/protos/peer"
	"bytes"
	"errors"
)

// TransactionId represents transaction identifier. TransactionId is the unique transaction number.
type TransactionId struct {
	Nonce         []byte
	TransactionId string
	Creator       []byte
}

// QueryResponse represent result from query operation
type QueryResponse struct {
	PeerName string
	Error    error
	Response *peer.ProposalResponse
}

// InvokeResponse represent result from invoke operation. Please note that this is the result of simulation,
// not the result of actual block commit.
type InvokeResponse struct {
	Status common.Status
	// TxID is transaction id. This id can be used to track transactions and their status
	TxID string
}

type BlockHeader struct {
	Number       uint64 `json:"blockNumber"`
	PreviousHash string `json:"previousHash"`
	DataHash     string `json:"dataHash"`
}

type BlockData struct {
	Data []*Envelope `json:"envelope"`
}

type BlockMetadata struct {
	Metadata []*Metadata `json:"metadata"`
}

type Metadata struct {
	Value      []byte               `json:"value"`
	Signatures []*MetadataSignature `json:"signatures"`
}

type MetadataSignature struct {
	SignatureHeader *SignatureHeader `json:"signatureHeader"`
	Signature       []byte           `json:"signature"`
}
type Block struct {
	Header   *BlockHeader   `json:"blockHeader"`
	Data     *BlockData     `json:"blockData"`
	Metadata *BlockMetadata `json:"blockMetadata"`
}

// QueryTransactionResponse holds data from `client.QueryTransaction`
// TODO it is not fully implemented!
//type QueryTransactionResponse struct {
//	PeerName   string
//	Error      error
//	StatusCode int32
//}

type TransactionProposal struct {
	proposal      []byte
	transactionId string
}

// QueryTransactionResponse holds data from `client.QueryTransaction`
// TODO it is not fully implemented!
type QueryTransactionResponse struct {
	PeerName             string                `json:"peerName"`
	Error                error                 `json:"error"`
	ProcessedTransaction *ProcessedTransaction `json:"processedTransaction"`
}
type ProcessedTransaction struct {
	TransactionEnvelope *Envelope `json:"transactionEnvelope"`
	ValidationCode      int       `json:"validationCode"`
}
type QueryBlockResponse struct {
	PeerName   string `json:"peerName"`
	Error      error  `json:"error,omitempty"`
	StatusCode int32  `json:"statusCode"`
	Block      *Block `json:"block"`
}
type Envelope struct {
	Payload   *Payload `json:"payload"`
	Signature string   `json:"signature"`
}
type Payload struct {
	Header *Header            `json:"header"`
	Data   *TransactionAction `json:"data"`
}

type Header struct {
	ChannelHeader   *ChannelHeader   `json:"channelHeader"`
	SignatureHeader *SignatureHeader `json:"signatureHeader"`
}
type SignatureHeader struct {
	Creator *Creator `json:"creator"`
	Nonce   string   `json:"nonce"`
}
type ChannelHeader struct {
	Type      int32                     `json:"type"`
	Version   int32                     `json:"version"`
	Timestamp int64                     `json:"timestamp"`
	ChannelId string                    `json:"channelId"`
	TxId      string                    `json:"txId"`
	Epoch     uint64                    `json:"epoch"`
	Extension *ChaincodeHeaderExtension `json:"extension,omitempty"`
}
type Creator struct {
	Mspid        string `json:"mspID"`
	SerializedId string `json:"serializedId"`
}
type ChaincodeHeaderExtension struct {
	PayloadVisibility []byte       `json:"payloadVisibility"`
	ChaincodeID       *ChaincodeID `json:"chaincodeId"`
}
type ChaincodeID struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Version string `json:"version"`
}
type TransactionAction struct {
	// This holgs the identity of the client which submitted this transaction
	Header  *SignatureHeader        `json:"header"`
	Payload *ChaincodeActionPayload `json:"payload"`
}
type ChaincodeActionPayload struct {
	ChaincodeProposalPayload *ChaincodeProposalPayload `json:"chaincodeProposalPayload"`
	Action                   *ChaincodeEndorsedAction  `json:"action"`
}

type ChaincodeEndorsedAction struct {
	ProposalResponsePayload *ProposalResponsePayload
	Endorsements            []*Endorsement
}
type ChaincodeInput struct {
	Args []string `json:"args"`
}
type ChaincodeSpec struct {
	Type        int32           `json:"type"`
	ChaincodeId *ChaincodeID    `json:"chaincodeId"`
	Input       *ChaincodeInput `json:"chaincodeInput"`
	Timeout     int32           `json:"timeout"`
}
type ChaincodeInvocationSpec struct {
	ChaincodeSpec   *ChaincodeSpec `json:"chaincodeSpec"`
	IdGenerationAlg string         `json:"idGenerationAlg"`
}
type ChaincodeProposalPayload struct {
	Input        *ChaincodeInvocationSpec `json:"input"`
	TransientMap map[string][]byte        `json:"transientMap"`
}
type ProposalResponsePayload struct {
	ProposalHash []byte
	Extension    *ChaincodeAction
}
type ChaincodeAction struct {
	Results  *TxReadWriteSet
	Events   []byte
	Response *Response
}
type TxReadWriteSet struct {
	DataModel int32
	NsRwset   []*NsReadWriteSet
}

type NsReadWriteSet struct {
	Namespace string
	Rwset     *KVRWSet
}

type KVRWSet struct {
	Reads            []*KVRead
	RangeQueriesInfo []*RangeQueryInfo
	Writes           []*KVWrite
}
type KVRead struct {
	Key     string
	Version *Version
}

// TODO Implement if needed
type RangeQueryInfo struct {
}

// TODO Implement if needed
type KVWrite struct {
}
type Version struct {
	BlockNum uint64
	TxNum    uint64
}

// TODO Not implemented
type Response struct {
}

type Endorsement struct {
	Endorser  *Creator `json:"endorser"`
	Signature string   `json:"signature"`
}

// marshalProtoIdentity creates SerializedIdentity from certificate and MSPid
func marshalProtoIdentity(identity Identity) ([]byte, error) {
	if len(identity.MspId) < 1 {
		return nil, ErrMspMissing
	}
	creator, err := proto.Marshal(&msp.SerializedIdentity{
		Mspid:   identity.MspId,
		IdBytes: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.Certificate.Raw})})
	if err != nil {
		return nil, err
	}
	return creator, nil
}

// signatureHeader creates and marshal new signature header proto from creator and transaction nonce
func signatureHeader(creator []byte, tx *TransactionId) ([]byte, error) {
	sh := new(common.SignatureHeader)
	sh.Creator = creator
	sh.Nonce = tx.Nonce
	shBytes, err := proto.Marshal(sh)
	if err != nil {
		return nil, err
	}
	return shBytes, nil
}

// header creates new common.header from signature header and channel header
func header(signatureHeader, channelHeader []byte) (*common.Header) {
	header := new(common.Header)
	header.SignatureHeader = signatureHeader
	header.ChannelHeader = channelHeader
	return header
}

func channelHeader(headerType common.HeaderType, tx *TransactionId, channelId string, epoch uint64, extension *peer.ChaincodeHeaderExtension) ([]byte, error) {
	ts, err := ptypes.TimestampProto(time.Now())
	if err != nil {
		return nil, err
	}
	var channelName string

	if len(channelId) > 0 {
		channelName = channelId
	}
	payloadChannelHeader := &common.ChannelHeader{
		Type:      int32(headerType),
		Version:   1,
		Timestamp: ts,
		ChannelId: channelName,
		Epoch:     epoch,
	}
	payloadChannelHeader.TxId = tx.TransactionId
	if extension != nil {
		serExt, err := proto.Marshal(extension)
		if err != nil {
			return nil, err
		}
		payloadChannelHeader.Extension = serExt
	}
	return proto.Marshal(payloadChannelHeader)
}

// payload creates new common.payload from commonHeader and envelope data
func payload(header *common.Header, data []byte) ([]byte, error) {
	p := new(common.Payload)
	p.Header = header
	p.Data = data
	return proto.Marshal(p)
}

// newTransactionId generate new transaction id from creator and random bytes
func newTransactionId(creator []byte) (*TransactionId, error) {
	nonce, err := generateRandomBytes(24)
	if err != nil {
		return nil, err
	}
	id := generateTxId(nonce, creator)
	return &TransactionId{Creator: creator, Nonce: nonce, TransactionId: id}, nil
}

// generateRandomBytes get random bytes from crypto/random
func generateRandomBytes(len int) ([]byte, error) {
	b := make([]byte, len)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// sha256 is hardcoded in hyperledger
func generateTxId(nonce, creator []byte) string {
	f := sha256.New()
	f.Write(append(nonce, creator...))
	return hex.EncodeToString(f.Sum(nil))
}

func chainCodeInvocationSpec(chainCode ChainCode) ([]byte, error) {

	invocation := &peer.ChaincodeInvocationSpec{
		ChaincodeSpec: &peer.ChaincodeSpec{
			Type:        peer.ChaincodeSpec_Type(chainCode.Type),
			ChaincodeId: &peer.ChaincodeID{Name: chainCode.Name},
			Input:       &peer.ChaincodeInput{Args: chainCode.toChainCodeArgs()},
		},
	}
	invocationBytes, err := proto.Marshal(invocation)
	if err != nil {
		return nil, err
	}
	return invocationBytes, nil
}

func proposal(header, payload []byte) ([]byte, error) {
	prop := new(peer.Proposal)
	prop.Header = header
	prop.Payload = payload

	propBytes, err := proto.Marshal(prop)
	if err != nil {
		return nil, err
	}
	return propBytes, nil
}

func signedProposal(prop []byte, identity Identity, crypt CryptoSuite) (*peer.SignedProposal, error) {
	sb, err := crypt.Sign(prop, identity.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &peer.SignedProposal{ProposalBytes: prop, Signature: sb}, nil
}

// sendToPeers send proposal to all peers in the list for endorsement asynchronously and wait for there response.
// there is no difference in what order results will e returned and is `p.Endorse()` guarantee that there will be
// response, so no need of complex synchronisation and wait groups
func sendToPeers(peers []*Peer, prop *peer.SignedProposal) []*PeerResponse {
	ch := make(chan *PeerResponse)
	l := len(peers)
	resp := make([]*PeerResponse, 0, l)
	for _, p := range peers {
		go p.Endorse(ch, prop)
	}
	for i := 0; i < l; i++ {
		resp = append(resp, <-ch)
	}
	close(ch)
	return resp
}

func CreateTransactionProposal(identity Identity, cc ChainCode) (*TransactionProposal, error) {
	spec, err := chainCodeInvocationSpec(cc)
	if err != nil {
		return nil, err
	}
	creator, err := marshalProtoIdentity(identity)
	if err != nil {
		return nil, err
	}
	txId, err := newTransactionId(creator)
	if err != nil {
		return nil, err
	}

	extension := &peer.ChaincodeHeaderExtension{ChaincodeId: &peer.ChaincodeID{Name: cc.Name}}
	channelHeader, err := channelHeader(common.HeaderType_ENDORSER_TRANSACTION, txId, cc.ChannelId, 0, extension)
	if err != nil {
		return nil, err
	}
	signatureHeader, err := signatureHeader(creator, txId)
	if err != nil {
		return nil, err
	}

	proposalPayload, err := proto.Marshal(&peer.ChaincodeProposalPayload{Input: spec, TransientMap: cc.TransientMap})
	if err != nil {
		return nil, err
	}

	header, err := proto.Marshal(header(signatureHeader, channelHeader))
	if err != nil {
		return nil, err
	}

	proposal, err := proposal(header, proposalPayload)
	if err != nil {
		return nil, err
	}
	return &TransactionProposal{proposal: proposal, transactionId: txId.TransactionId}, nil
}

func decodeChainCodeQueryResponse(data []byte) ([]*peer.ChaincodeInfo, error) {
	response := new(peer.ChaincodeQueryResponse)
	err := proto.Unmarshal(data, response)
	if err != nil {
		return nil, err
	}
	return response.GetChaincodes(), nil
}

func CreateTransaction(proposal []byte, endorsement []*PeerResponse) ([]byte, error) {
	var propResp *peer.ProposalResponse
	var pl []byte
	mEndorsements := make([]*peer.Endorsement, 0, len(endorsement))
	for _, e := range endorsement {
		if e.Err == nil && e.Response.Response.Status == 200 {
			propResp = e.Response
			mEndorsements = append(mEndorsements, e.Response.Endorsement)
			if pl == nil {
				pl = e.Response.Payload
			}
		} else {
			if e.Err != nil {
				return nil, e.Err
			}
			return nil, ErrBadTransactionStatus
		}
		if bytes.Compare(pl, e.Response.Payload) != 0 {
			return nil, ErrEndorsementsDoNotMatch
		}
	}

	// at least one is OK
	if len(mEndorsements) < 1 {
		return nil, ErrNoValidEndorsementFound
	}

	originalProposal, err := getProposal(proposal)
	if err != nil {
		return nil, err
	}

	originalProposalHeader, err := getHeader(originalProposal.Header)
	if err != nil {
		return nil, err
	}

	originalProposalPayload, err := getChainCodeProposalPayload(originalProposal.Payload)
	if err != nil {
		return nil, err
	}

	// create actual invocation

	proposedPayload, err := proto.Marshal(&peer.ChaincodeProposalPayload{Input: originalProposalPayload.Input, TransientMap: nil})
	if err != nil {
		return nil, err
	}

	payload, err := proto.Marshal(&peer.ChaincodeActionPayload{
		Action: &peer.ChaincodeEndorsedAction{
			ProposalResponsePayload: propResp.Payload,
			Endorsements:            mEndorsements,
		},
		ChaincodeProposalPayload: proposedPayload,
	})
	if err != nil {
		return nil, err
	}

	sTransaction, err := proto.Marshal(&peer.Transaction{
		Actions: []*peer.TransactionAction{{Header: originalProposalHeader.SignatureHeader, Payload: payload}},
	})
	if err != nil {
		return nil, err
	}

	propBytes, err := proto.Marshal(&common.Payload{Header: originalProposalHeader, Data: sTransaction})
	if err != nil {
		return nil, err
	}
	return propBytes, nil
}

func getProposal(data []byte) (*peer.Proposal, error) {
	prop := new(peer.Proposal)
	err := proto.Unmarshal(data, prop)
	if err != nil {
		return nil, err
	}
	return prop, nil
}

func getHeader(bytes []byte) (*common.Header, error) {
	h := &common.Header{}
	err := proto.Unmarshal(bytes, h)
	if err != nil {
		return nil, err
	}
	return h, err
}

func getChainCodeProposalPayload(bytes []byte) (*peer.ChaincodeProposalPayload, error) {
	cpp := &peer.ChaincodeProposalPayload{}
	err := proto.Unmarshal(bytes, cpp)
	if err != nil {
		return nil, err
	}
	return cpp, err
}

func decodeBlock(payload []byte) (*QueryBlockResponse, error) {
	block := new(common.Block)
	if err := proto.Unmarshal(payload, block); err != nil {
		return nil, err
	}

	numOfEnvelopes := len(block.Data.Data)
	envelopes := make([]*Envelope, numOfEnvelopes)
	for idx, obj := range block.Data.Data {
		envelope := new(common.Envelope)
		if err := proto.Unmarshal(obj, envelope); err != nil {
			return nil, err
		}
		decPayload, err := decodeTransactionEnvelopePayload(envelope.Payload)
		if err != nil {
			return nil, err
		}
		envelopes[idx] = &Envelope{
			Payload:   decPayload,
			Signature: hex.EncodeToString(envelope.Signature[:]),
		}
	}

	if len(block.Metadata.Metadata) == 0 {
		return nil, errors.New("Metadata array is empty")
	}
	metadata := new(common.Metadata)
	if err := proto.Unmarshal(block.Metadata.Metadata[0], metadata); err != nil {
		return nil, err
	}
	signatures := make([]*MetadataSignature, len(metadata.Signatures))
	for idx, signatureObj := range metadata.Signatures {
		pbSignatureHeader := new(common.SignatureHeader)
		if err := proto.Unmarshal(signatureObj.SignatureHeader, pbSignatureHeader); err != nil {
			return nil, err
		}
		identity := new(msp.SerializedIdentity)
		if err := proto.Unmarshal(pbSignatureHeader.Creator, identity); err != nil {
			return nil, err
		}
		signatures[idx] = &MetadataSignature{
			SignatureHeader: &SignatureHeader{
				Creator: &Creator{
					Mspid:        identity.Mspid,
					SerializedId: string(identity.IdBytes[:]),
				},
				Nonce: hex.EncodeToString(pbSignatureHeader.Nonce[:]),
			},
			Signature: signatureObj.Signature[:],
		}
	}

	responseObj := QueryBlockResponse{
		Block: &Block{
			Header: &BlockHeader{
				Number:       block.Header.Number,
				PreviousHash: hex.EncodeToString(block.Header.PreviousHash[:]),
				DataHash:     hex.EncodeToString(block.Header.DataHash[:]),
			},
			Data: &BlockData{
				Data: envelopes,
			},
			Metadata: &BlockMetadata{
				Metadata: []*Metadata{
					&Metadata{
						Value:      metadata.Value[:],
						Signatures: signatures,
					}},
			},
		},
	}
	return &responseObj, nil
}
func decodeTransactionEnvelopePayload(payload []byte) (*Payload, error) {
	transacionEnvelopePayload := new(common.Payload)
	if err := proto.Unmarshal(payload, transacionEnvelopePayload); err != nil {
		return nil, err
	}

	channelHeader := new(common.ChannelHeader)
	if err := proto.Unmarshal(transacionEnvelopePayload.Header.ChannelHeader, channelHeader); err != nil {
		return nil, err
	}
	signatureHeader := new(common.SignatureHeader)
	if err := proto.Unmarshal(transacionEnvelopePayload.Header.SignatureHeader, signatureHeader); err != nil {
		return nil, err
	}
	transactionSigneeIdentity := new(msp.SerializedIdentity)
	if err := proto.Unmarshal(signatureHeader.Creator, transactionSigneeIdentity); err != nil {
		return nil, err
	}
	chaincodeHeaderExtension := new(peer.ChaincodeHeaderExtension)
	if err := proto.Unmarshal(channelHeader.Extension, chaincodeHeaderExtension); err != nil {
		return nil, err
	}

	transactionAction := new(peer.Transaction)
	if err := proto.Unmarshal(transacionEnvelopePayload.Data, transactionAction); err != nil {
		return nil, err
	}

	peerSignatureheader := new(common.SignatureHeader)
	if err := proto.Unmarshal(transactionAction.Actions[0].Header, peerSignatureheader); err != nil {
		return nil, err
	}

	cPayload, err := GetChaincodeActionPayload(transactionAction.Actions[0].Payload)
	if err != nil {
		return nil, err
	}

	cProposalPayload := new(peer.ChaincodeProposalPayload)
	if err := proto.Unmarshal(cPayload.ChaincodeProposalPayload, cProposalPayload); err != nil {
		return nil, err
	}

	cInvocationSpec := new(peer.ChaincodeInvocationSpec)
	if err := proto.Unmarshal(cProposalPayload.Input, cInvocationSpec); err != nil {
		return nil, err
	}

	cInvocationArgs := make([]string, len(cInvocationSpec.ChaincodeSpec.Input.Args))
	for idx, arg := range cInvocationSpec.ChaincodeSpec.Input.Args {
		cInvocationArgs[idx] = string(arg)
	}

	endorsers := make([]*Endorsement, len(cPayload.Action.Endorsements))
	for idx, endorser := range cPayload.Action.Endorsements {
		endorserIdentity := new(msp.SerializedIdentity)
		if err := proto.Unmarshal(endorser.Endorser, endorserIdentity); err != nil {
			return nil, err
		}
		endorsers[idx] = &Endorsement{
			Endorser: &Creator{
				Mspid:        endorserIdentity.Mspid,
				SerializedId: string(endorserIdentity.IdBytes),
			},
			Signature: hex.EncodeToString(endorser.Signature),
		}
	}

	comittingPeerIdentity := new(msp.SerializedIdentity)
	if err := proto.Unmarshal(peerSignatureheader.Creator[:], comittingPeerIdentity); err != nil {
		return nil, err
	}
	return &Payload{
		Header: &Header{
			ChannelHeader: &ChannelHeader{
				Type:      channelHeader.Type,
				Version:   channelHeader.Version,
				Timestamp: channelHeader.Timestamp.Seconds,
				ChannelId: channelHeader.ChannelId,
				TxId:      channelHeader.TxId,
				Epoch:     channelHeader.Epoch,
				Extension: &ChaincodeHeaderExtension{
					PayloadVisibility: chaincodeHeaderExtension.PayloadVisibility[:],
					ChaincodeID: &ChaincodeID{
						Path:    chaincodeHeaderExtension.ChaincodeId.Path,
						Name:    chaincodeHeaderExtension.ChaincodeId.Name,
						Version: chaincodeHeaderExtension.ChaincodeId.Version,
					},
				},
			},
			SignatureHeader: &SignatureHeader{
				Creator: &Creator{
					Mspid:        transactionSigneeIdentity.Mspid,
					SerializedId: string(transactionSigneeIdentity.IdBytes[:]),
				},
				Nonce: hex.EncodeToString(signatureHeader.Nonce[:]),
			},
		},
		Data: &TransactionAction{
			Header: &SignatureHeader{
				Creator: &Creator{
					Mspid:        comittingPeerIdentity.Mspid,
					SerializedId: string(comittingPeerIdentity.IdBytes),
				},
				Nonce: hex.EncodeToString(peerSignatureheader.Nonce[:]),
			},
			Payload: &ChaincodeActionPayload{
				ChaincodeProposalPayload: &ChaincodeProposalPayload{
					Input: &ChaincodeInvocationSpec{
						ChaincodeSpec: &ChaincodeSpec{
							Type: int32(cInvocationSpec.ChaincodeSpec.Type),
							ChaincodeId: &ChaincodeID{
								Path:    cInvocationSpec.ChaincodeSpec.ChaincodeId.Path,
								Name:    cInvocationSpec.ChaincodeSpec.ChaincodeId.Name,
								Version: cInvocationSpec.ChaincodeSpec.ChaincodeId.Version,
							},
							Input: &ChaincodeInput{
								Args: cInvocationArgs,
							},
							Timeout: cInvocationSpec.ChaincodeSpec.Timeout,
						},
						IdGenerationAlg: cInvocationSpec.IdGenerationAlg,
					},
					TransientMap: cProposalPayload.TransientMap,
				},
				Action: &ChaincodeEndorsedAction{
					Endorsements: endorsers,
				},
			},
		},
	}, nil
}

// TODO not fully implemented!
func decodeTransaction(payload []byte) (*QueryTransactionResponse, error) {
	transaction := new(peer.ProcessedTransaction)
	if err := proto.Unmarshal(payload, transaction); err != nil {
		return nil, err
	}
	decPayload, err := decodeTransactionEnvelopePayload(transaction.TransactionEnvelope.Payload)
	if err != nil {
		return nil, err
	}
	responseObj := QueryTransactionResponse{
		ProcessedTransaction: &ProcessedTransaction{
			TransactionEnvelope: &Envelope{
				Payload:   decPayload,
				Signature: hex.EncodeToString(transaction.TransactionEnvelope.Signature[:]),
			},
			ValidationCode: int(transaction.ValidationCode),
		},
	}

	return &responseObj, nil

}
