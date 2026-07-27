package contracts

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func EventSigningMessage(event EventEnvelopeV1) ([]byte, error) {
	raw, err := CanonicalJSON(event)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	documentValue, err := strictValue(decoder)
	if err != nil {
		return nil, err
	}
	document, ok := documentValue.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("event must canonicalize as an object")
	}
	delete(document, "source_signature")
	canonical, err := CanonicalJSON(document)
	if err != nil {
		return nil, err
	}
	return append([]byte("AGMIND_EVENT_ENVELOPE_V1\x00"), canonical...), nil
}

func VerifyEventSignature(event EventEnvelopeV1, publicKey ed25519.PublicKey) error {
	signature, err := hex.DecodeString(event.SourceSignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid source signature")
	}
	message, err := EventSigningMessage(event)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return fmt.Errorf("invalid source signature")
	}
	return nil
}

func validateContract(value any) error {
	switch typed := value.(type) {
	case EventEnvelopeV1:
		return validateEventEnvelope(typed)
	case TemporaryEgressDenyIntentV1:
		return validateIntent(typed)
	}
	return nil
}
