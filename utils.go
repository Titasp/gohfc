package gohfc

import (
	"github.com/golang/protobuf/proto"
	"fmt"
	cb "github.com/hyperledger/fabric/protos/common"
	pb "github.com/hyperledger/fabric/protos/peer"
	"github.com/pkg/errors"
)

// UnmarshalChaincodeID returns a ChaincodeID from bytes
func UnmarshalChaincodeID(bytes []byte) (*pb.ChaincodeID, error) {
	ccid := &pb.ChaincodeID{}
	err := proto.Unmarshal(bytes, ccid)
	if err != nil {
		return nil, fmt.Errorf("UnmarshalChaincodeID failed, err %s", err)
	}

	return ccid, nil
}

// UnmarshalPayloadOrPanic unmarshals bytes to a Payload structure or panics on error
func UnmarshalPayloadOrPanic(encoded []byte) *cb.Payload {
	payload, err := UnmarshalPayload(encoded)
	if err != nil {
		panic(fmt.Errorf("Error unmarshaling data to payload: %s", err))
	}
	return payload
}

// UnmarshalPayload unmarshals bytes to a Payload structure
func UnmarshalPayload(encoded []byte) (*cb.Payload, error) {
	payload := &cb.Payload{}
	err := proto.Unmarshal(encoded, payload)
	if err != nil {
		return nil, err
	}
	return payload, err
}

// UnmarshalEnvelopeOrPanic unmarshals bytes to an Envelope structure or panics on error
func UnmarshalEnvelopeOrPanic(encoded []byte) *cb.Envelope {
	envelope, err := UnmarshalEnvelope(encoded)
	if err != nil {
		panic(fmt.Errorf("Error unmarshaling data to envelope: %s", err))
	}
	return envelope
}

// UnmarshalEnvelope unmarshals bytes to an Envelope structure
func UnmarshalEnvelope(encoded []byte) (*cb.Envelope, error) {
	envelope := &cb.Envelope{}
	err := proto.Unmarshal(encoded, envelope)
	if err != nil {
		return nil, err
	}
	return envelope, err
}

// UnmarshalEnvelopeOfType unmarshals an envelope of the specified type, including
// the unmarshaling the payload data
func UnmarshalEnvelopeOfType(envelope *cb.Envelope, headerType cb.HeaderType, message proto.Message) (*cb.ChannelHeader, error) {
	payload, err := UnmarshalPayload(envelope.Payload)
	if err != nil {
		return nil, err
	}

	if payload.Header == nil {
		return nil, fmt.Errorf("Envelope must have a Header")
	}

	chdr, err := UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return nil, fmt.Errorf("Invalid ChannelHeader")
	}

	if chdr.Type != int32(headerType) {
		return nil, fmt.Errorf("Not a tx of type %v", headerType)
	}

	if err = proto.Unmarshal(payload.Data, message); err != nil {
		return nil, fmt.Errorf("Error unmarshaling message for type %v: %s", headerType, err)
	}

	return chdr, nil
}

// ExtractEnvelopeOrPanic retrieves the requested envelope from a given block and unmarshals it -- it panics if either of these operation fail.
func ExtractEnvelopeOrPanic(block *cb.Block, index int) *cb.Envelope {
	envelope, err := ExtractEnvelope(block, index)
	if err != nil {
		panic(err)
	}
	return envelope
}

// ExtractEnvelope retrieves the requested envelope from a given block and unmarshals it.
func ExtractEnvelope(block *cb.Block, index int) (*cb.Envelope, error) {
	if block.Data == nil {
		return nil, fmt.Errorf("No data in block")
	}

	envelopeCount := len(block.Data.Data)
	if index < 0 || index >= envelopeCount {
		return nil, fmt.Errorf("Envelope index out of bounds")
	}
	marshaledEnvelope := block.Data.Data[index]
	envelope, err := GetEnvelopeFromBlock(marshaledEnvelope)
	if err != nil {
		return nil, fmt.Errorf("Block data does not carry an envelope at index %d: %s", index, err)
	}
	return envelope, nil
}

// ExtractPayloadOrPanic retrieves the payload of a given envelope and unmarshals it -- it panics if either of these operations fail.
func ExtractPayloadOrPanic(envelope *cb.Envelope) *cb.Payload {
	payload, err := ExtractPayload(envelope)
	if err != nil {
		panic(err)
	}
	return payload
}

// ExtractPayload retrieves the payload of a given envelope and unmarshals it.
func ExtractPayload(envelope *cb.Envelope) (*cb.Payload, error) {
	payload := &cb.Payload{}
	if err := proto.Unmarshal(envelope.Payload, payload); err != nil {
		return nil, fmt.Errorf("Envelope does not carry a Payload: %s", err)
	}
	return payload, nil
}

// UnmarshalChannelHeader returns a ChannelHeader from bytes
func UnmarshalChannelHeader(bytes []byte) (*cb.ChannelHeader, error) {
	chdr := &cb.ChannelHeader{}
	err := proto.Unmarshal(bytes, chdr)
	if err != nil {
		return nil, fmt.Errorf("UnmarshalChannelHeader failed, err %s", err)
	}

	return chdr, nil
}

// GetEnvelopeFromBlock gets an envelope from a block's Data field.
func GetEnvelopeFromBlock(data []byte) (*cb.Envelope, error) {
	//Block always begins with an envelope
	var err error
	env := &cb.Envelope{}
	if err = proto.Unmarshal(data, env); err != nil {
		return nil, fmt.Errorf("Error getting envelope(%s)", err)
	}

	return env, nil
}

// GetPayloads get's the underlying payload objects in a TransactionAction
func GetPayloads(txActions *pb.TransactionAction) (*pb.ChaincodeActionPayload, *pb.ChaincodeAction, error) {
	// TODO: pass in the tx type (in what follows we're assuming the type is ENDORSER_TRANSACTION)
	ccPayload := &pb.ChaincodeActionPayload{}
	err := proto.Unmarshal(txActions.Payload, ccPayload)
	if err != nil {
		return nil, nil, err
	}

	if ccPayload.Action == nil || ccPayload.Action.ProposalResponsePayload == nil {
		return nil, nil, fmt.Errorf("no payload in ChaincodeActionPayload")
	}
	pRespPayload := &pb.ProposalResponsePayload{}
	err = proto.Unmarshal(ccPayload.Action.ProposalResponsePayload, pRespPayload)
	if err != nil {
		return nil, nil, err
	}

	if pRespPayload.Extension == nil {
		return nil, nil, fmt.Errorf("response payload is missing extension")
	}

	respPayload := &pb.ChaincodeAction{}
	err = proto.Unmarshal(pRespPayload.Extension, respPayload)
	if err != nil {
		return ccPayload, nil, err
	}
	return ccPayload, respPayload, nil
}

// GetHeader Get Header from bytes
func GetHeader(bytes []byte) (*cb.Header, error) {
	hdr := &cb.Header{}
	err := proto.Unmarshal(bytes, hdr)
	return hdr, err
}

// GetNonce returns the nonce used in Proposal
func GetNonce(prop *pb.Proposal) ([]byte, error) {
	if prop == nil {
		return nil, fmt.Errorf("Proposal is nil")
	}
	// get back the header
	hdr, err := GetHeader(prop.Header)
	if err != nil {
		return nil, fmt.Errorf("Could not extract the header from the proposal: %s", err)
	}

	chdr, err := UnmarshalChannelHeader(hdr.ChannelHeader)
	if err != nil {
		return nil, fmt.Errorf("Could not extract the channel header from the proposal: %s", err)
	}

	if cb.HeaderType(chdr.Type) != cb.HeaderType_ENDORSER_TRANSACTION &&
		cb.HeaderType(chdr.Type) != cb.HeaderType_CONFIG {
		return nil, fmt.Errorf("Invalid proposal type expected ENDORSER_TRANSACTION or CONFIG. Was: %d", chdr.Type)
	}

	shdr, err := GetSignatureHeader(hdr.SignatureHeader)
	if err != nil {
		return nil, fmt.Errorf("Could not extract the signature header from the proposal: %s", err)
	}

	if hdr.SignatureHeader == nil {
		return nil, errors.New("Invalid signature header. It must be different from nil.")
	}

	return shdr.Nonce, nil
}

// GetChaincodeAction gets the ChaincodeAction given chaicnode action bytes
func GetChaincodeAction(caBytes []byte) (*pb.ChaincodeAction, error) {
	chaincodeAction := &pb.ChaincodeAction{}
	err := proto.Unmarshal(caBytes, chaincodeAction)
	return chaincodeAction, err
}

// GetResponse gets the Response given response bytes
func GetResponse(resBytes []byte) (*pb.Response, error) {
	response := &pb.Response{}
	err := proto.Unmarshal(resBytes, response)
	return response, err
}

// GetChaincodeEvents gets the ChaincodeEvents given chaicnode event bytes
func GetChaincodeEvents(eBytes []byte) (*pb.ChaincodeEvent, error) {
	chaincodeEvent := &pb.ChaincodeEvent{}
	err := proto.Unmarshal(eBytes, chaincodeEvent)
	return chaincodeEvent, err
}

// GetProposalResponsePayload gets the proposal response payload
func GetProposalResponsePayload(prpBytes []byte) (*pb.ProposalResponsePayload, error) {
	prp := &pb.ProposalResponsePayload{}
	err := proto.Unmarshal(prpBytes, prp)
	return prp, err
}

// GetProposal returns a Proposal message from its bytes
func GetProposal(propBytes []byte) (*pb.Proposal, error) {
	prop := &pb.Proposal{}
	err := proto.Unmarshal(propBytes, prop)
	return prop, err
}

// GetPayload Get Payload from Envelope message
func GetPayload(e *cb.Envelope) (*cb.Payload, error) {
	payload := &cb.Payload{}
	err := proto.Unmarshal(e.Payload, payload)
	return payload, err
}

// GetTransaction Get Transaction from bytes
func GetTransaction(txBytes []byte) (*pb.Transaction, error) {
	tx := &pb.Transaction{}
	err := proto.Unmarshal(txBytes, tx)
	return tx, err
}

// GetChaincodeActionPayload Get ChaincodeActionPayload from bytes
func GetChaincodeActionPayload(capBytes []byte) (*pb.ChaincodeActionPayload, error) {
	cap := &pb.ChaincodeActionPayload{}
	err := proto.Unmarshal(capBytes, cap)
	return cap, err
}

// GetChaincodeProposalPayload Get ChaincodeProposalPayload from bytes
func GetChaincodeProposalPayload(bytes []byte) (*pb.ChaincodeProposalPayload, error) {
	cpp := &pb.ChaincodeProposalPayload{}
	err := proto.Unmarshal(bytes, cpp)
	return cpp, err
}

// GetSignatureHeader Get SignatureHeader from bytes
func GetSignatureHeader(bytes []byte) (*cb.SignatureHeader, error) {
	sh := &cb.SignatureHeader{}
	err := proto.Unmarshal(bytes, sh)
	return sh, err
}

// GetChaincodeHeaderExtension get chaincode header extension given header
func GetChaincodeHeaderExtension(hdr *cb.Header) (*pb.ChaincodeHeaderExtension, error) {
	chdr, err := UnmarshalChannelHeader(hdr.ChannelHeader)
	if err != nil {
		return nil, err
	}

	chaincodeHdrExt := &pb.ChaincodeHeaderExtension{}
	err = proto.Unmarshal(chdr.Extension, chaincodeHdrExt)
	return chaincodeHdrExt, err
}

// GetProposalResponse given proposal in bytes
func GetProposalResponse(prBytes []byte) (*pb.ProposalResponse, error) {
	proposalResponse := &pb.ProposalResponse{}
	err := proto.Unmarshal(prBytes, proposalResponse)
	return proposalResponse, err
}

// GetBytesProposalResponsePayload gets proposal response payload
func GetBytesProposalResponsePayload(hash []byte, response *pb.Response, result []byte, event []byte, ccid *pb.ChaincodeID) ([]byte, error) {
	cAct := &pb.ChaincodeAction{Events: event, Results: result, Response: response, ChaincodeId: ccid}
	cActBytes, err := proto.Marshal(cAct)
	if err != nil {
		return nil, err
	}

	prp := &pb.ProposalResponsePayload{Extension: cActBytes, ProposalHash: hash}
	prpBytes, err := proto.Marshal(prp)
	return prpBytes, err
}

// GetBytesChaincodeProposalPayload gets the chaincode proposal payload
func GetBytesChaincodeProposalPayload(cpp *pb.ChaincodeProposalPayload) ([]byte, error) {
	cppBytes, err := proto.Marshal(cpp)
	return cppBytes, err
}

// GetBytesResponse gets the bytes of Response
func GetBytesResponse(res *pb.Response) ([]byte, error) {
	resBytes, err := proto.Marshal(res)
	return resBytes, err
}

// GetBytesChaincodeEvent gets the bytes of ChaincodeEvent
func GetBytesChaincodeEvent(event *pb.ChaincodeEvent) ([]byte, error) {
	eventBytes, err := proto.Marshal(event)
	return eventBytes, err
}

// GetBytesChaincodeActionPayload get the bytes of ChaincodeActionPayload from the message
func GetBytesChaincodeActionPayload(cap *pb.ChaincodeActionPayload) ([]byte, error) {
	capBytes, err := proto.Marshal(cap)
	return capBytes, err
}

// GetBytesProposalResponse gets propoal bytes response
func GetBytesProposalResponse(pr *pb.ProposalResponse) ([]byte, error) {
	respBytes, err := proto.Marshal(pr)
	return respBytes, err
}

// GetBytesProposal returns the bytes of a proposal message
func GetBytesProposal(prop *pb.Proposal) ([]byte, error) {
	propBytes, err := proto.Marshal(prop)
	return propBytes, err
}

// GetBytesHeader get the bytes of Header from the message
func GetBytesHeader(hdr *cb.Header) ([]byte, error) {
	bytes, err := proto.Marshal(hdr)
	return bytes, err
}

// GetBytesSignatureHeader get the bytes of SignatureHeader from the message
func GetBytesSignatureHeader(hdr *cb.SignatureHeader) ([]byte, error) {
	bytes, err := proto.Marshal(hdr)
	return bytes, err
}

// GetBytesTransaction get the bytes of Transaction from the message
func GetBytesTransaction(tx *pb.Transaction) ([]byte, error) {
	bytes, err := proto.Marshal(tx)
	return bytes, err
}

// GetBytesPayload get the bytes of Payload from the message
func GetBytesPayload(payl *cb.Payload) ([]byte, error) {
	bytes, err := proto.Marshal(payl)
	return bytes, err
}

// GetBytesEnvelope get the bytes of Envelope from the message
func GetBytesEnvelope(env *cb.Envelope) ([]byte, error) {
	bytes, err := proto.Marshal(env)
	return bytes, err
}

// GetActionFromEnvelope extracts a ChaincodeAction message from a serialized Envelope
func GetActionFromEnvelope(envBytes []byte) (*pb.ChaincodeAction, error) {
	env, err := GetEnvelopeFromBlock(envBytes)
	if err != nil {
		return nil, err
	}

	payl, err := GetPayload(env)
	if err != nil {
		return nil, err
	}

	tx, err := GetTransaction(payl.Data)
	if err != nil {
		return nil, err
	}

	if len(tx.Actions) == 0 {
		return nil, fmt.Errorf("At least one TransactionAction is required")
	}

	_, respPayload, err := GetPayloads(tx.Actions[0])
	return respPayload, err
}
