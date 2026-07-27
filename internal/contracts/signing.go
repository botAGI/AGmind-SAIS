package contracts

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func canonicalDocumentWithout(value any, fields ...string) ([]byte, error) {
	raw, err := json.Marshal(value)
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
		return nil, fmt.Errorf("contract must canonicalize as an object")
	}
	for _, field := range fields {
		delete(document, field)
	}
	return CanonicalJSON(document)
}

func EventSigningMessage(event EventEnvelopeV1) ([]byte, error) {
	canonical, err := canonicalDocumentWithout(event, "source_signature")
	if err != nil {
		return nil, err
	}
	return append([]byte("AGMIND_EVENT_ENVELOPE_V1\x00"), canonical...), nil
}

func VerifyEventSignature(event EventEnvelopeV1, publicKey ed25519.PublicKey) error {
	derived, err := KeyID(publicKey)
	if err != nil {
		return err
	}
	if derived != event.KeyID {
		return fmt.Errorf("event key_id does not bind supplied public key")
	}
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

func ActionRecordSigningMessage(record ActionRecordV1) ([]byte, error) {
	canonical, err := canonicalDocumentWithout(record, "actuator_signature")
	if err != nil {
		return nil, err
	}
	return append([]byte("AGMIND_ACTION_RECORD_V1\x00"), canonical...), nil
}

func VerifyActionRecord(record ActionRecordV1, publicKey ed25519.PublicKey) error {
	derived, err := KeyID(publicKey)
	if err != nil {
		return err
	}
	if derived != record.ActuatorKeyID {
		return fmt.Errorf("actuator_key_id does not bind supplied public key")
	}
	if err := record.Validate(); err != nil {
		return err
	}
	signature, err := hex.DecodeString(record.ActuatorSignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid actuator signature")
	}
	message, err := ActionRecordSigningMessage(record)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return fmt.Errorf("invalid actuator signature")
	}
	return nil
}

// KeyTransitionSigningMessage resolves the plan's previously implicit
// dual-signature preimage. Both keys sign these exact same bytes.
func KeyTransitionSigningMessage(transition KeyTransitionV1) ([]byte, error) {
	canonical, err := canonicalDocumentWithout(
		transition,
		"old_signature",
		"new_signature",
	)
	if err != nil {
		return nil, err
	}
	return append([]byte("AGMIND_KEY_TRANSITION_V1\x00"), canonical...), nil
}

func VerifyKeyTransition(
	transition KeyTransitionV1,
	oldPublicKey ed25519.PublicKey,
) error {
	if err := transition.Validate(); err != nil {
		return err
	}
	oldID, err := KeyID(oldPublicKey)
	if err != nil {
		return err
	}
	if oldID != transition.OldKeyID {
		return fmt.Errorf("old_key_id does not bind supplied public key")
	}
	newPublicKey, err := hex.DecodeString(transition.NewPublicKey)
	if err != nil || len(newPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid new public key")
	}
	newID, err := KeyID(newPublicKey)
	if err != nil {
		return err
	}
	if newID != transition.NewKeyID {
		return fmt.Errorf("new_key_id does not bind new public key")
	}
	oldSignature, err := hex.DecodeString(transition.OldSignature)
	if err != nil || len(oldSignature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid old transition signature")
	}
	newSignature, err := hex.DecodeString(transition.NewSignature)
	if err != nil || len(newSignature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid new transition signature")
	}
	message, err := KeyTransitionSigningMessage(transition)
	if err != nil {
		return err
	}
	if !ed25519.Verify(oldPublicKey, message, oldSignature) {
		return fmt.Errorf("invalid old transition signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(newPublicKey), message, newSignature) {
		return fmt.Errorf("invalid new transition signature")
	}
	return nil
}
