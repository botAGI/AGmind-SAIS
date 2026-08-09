package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"runtime"
	"strings"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

const (
	hostIDPath          = "/var/lib/agmind-sais/identity/host-id"
	observerKeyPath     = "/etc/agmind-sais/secrets/observer-ed25519.key"
	observerTrustPath   = "/etc/agmind-sais/observer-trust-root.json"
	actuatorKeyPath     = "/etc/agmind-sais/secrets/actuator-ed25519.key"
	actuatorPublicPath  = "/etc/agmind-sais/public/actuator-ed25519.pub"
	coreAPITokenPath    = "/etc/agmind-sais/secrets/core-api.token"
	dgxAPITokenPath     = "/etc/agmind-sais/secrets/dgx-api.token"
	maxTrustRootBytes   = int64(4_096)
	maxTokenBytes       = 4_096
	generatedTokenBytes = 32
)

var hostIDPattern = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
)

type artifactSpec struct {
	name         string
	path         string
	maxBytes     int64
	allowedModes []fs.FileMode
}

type artifactState struct {
	present bool
	raw     []byte
}

type bootstrapResultV1 struct {
	SchemaVersion string            `json:"schema_version"`
	HostID        string            `json:"host_id"`
	ObserverKeyID string            `json:"observer_key_id"`
	ActuatorKeyID string            `json:"actuator_key_id"`
	Artifacts     map[string]string `json:"artifacts"`
}

var (
	hostIDArtifact = artifactSpec{
		name:         "host_id",
		path:         hostIDPath,
		maxBytes:     128,
		allowedModes: []fs.FileMode{0o600, 0o400},
	}
	observerKeyArtifact = artifactSpec{
		name:         "observer_private_key",
		path:         observerKeyPath,
		maxBytes:     ed25519.PrivateKeySize,
		allowedModes: []fs.FileMode{0o600, 0o400},
	}
	observerTrustArtifact = artifactSpec{
		name:         "observer_trust_root",
		path:         observerTrustPath,
		maxBytes:     maxTrustRootBytes,
		allowedModes: []fs.FileMode{0o600, 0o444},
	}
	actuatorKeyArtifact = artifactSpec{
		name:         "actuator_private_key",
		path:         actuatorKeyPath,
		maxBytes:     ed25519.PrivateKeySize,
		allowedModes: []fs.FileMode{0o600, 0o400},
	}
	actuatorPublicArtifact = artifactSpec{
		name:         "actuator_public_key",
		path:         actuatorPublicPath,
		maxBytes:     ed25519.PublicKeySize,
		allowedModes: []fs.FileMode{0o600, 0o444},
	}
	coreTokenArtifact = artifactSpec{
		name:         "core_api_token",
		path:         coreAPITokenPath,
		maxBytes:     maxTokenBytes + 1,
		allowedModes: []fs.FileMode{0o600, 0o640},
	}
	dgxTokenArtifact = artifactSpec{
		name:         "dgx_api_token",
		path:         dgxAPITokenPath,
		maxBytes:     maxTokenBytes + 1,
		allowedModes: []fs.FileMode{0o600, 0o640},
	}
)

func readArtifact(spec artifactSpec) (artifactState, error) {
	raw, err := durablefile.ReadTrustedRoot(
		spec.path,
		spec.maxBytes,
		spec.allowedModes...,
	)
	if err == nil {
		return artifactState{present: true, raw: raw}, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return artifactState{}, nil
	}
	return artifactState{}, fmt.Errorf("%s is unsafe or unreadable: %w", spec.name, err)
}

func readAllArtifacts() (map[string]artifactState, error) {
	states := make(map[string]artifactState, 7)
	for _, spec := range []artifactSpec{
		hostIDArtifact,
		observerKeyArtifact,
		observerTrustArtifact,
		actuatorKeyArtifact,
		actuatorPublicArtifact,
		coreTokenArtifact,
		dgxTokenArtifact,
	} {
		state, err := readArtifact(spec)
		if err != nil {
			return nil, err
		}
		states[spec.name] = state
	}
	return states, nil
}

func parseHostID(raw []byte) (string, error) {
	value := strings.TrimSuffix(string(raw), "\n")
	if !hostIDPattern.MatchString(value) {
		return "", fmt.Errorf("host ID is not a lowercase UUIDv4")
	}
	return value, nil
}

func generateHostID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", fmt.Errorf("generate host ID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	hexValue := hex.EncodeToString(value[:])
	return hexValue[0:8] + "-" +
		hexValue[8:12] + "-" +
		hexValue[12:16] + "-" +
		hexValue[16:20] + "-" +
		hexValue[20:32], nil
}

func validatePrivateKey(raw []byte, label string) (ed25519.PrivateKey, error) {
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s must be a raw 64-byte Ed25519 private key", label)
	}
	derived := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(raw, derived) != 1 {
		return nil, fmt.Errorf("%s seed/public binding is invalid", label)
	}
	return append(ed25519.PrivateKey(nil), raw...), nil
}

func generatePrivateKey(label string) (ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate %s: %w", label, err)
	}
	return privateKey, nil
}

func publicKey(privateKey ed25519.PrivateKey) ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), privateKey[ed25519.SeedSize:]...)
}

func expectedTrustRoot(
	hostID string,
	observerPublic ed25519.PublicKey,
) (contracts.ObserverTrustRootV1, []byte, error) {
	keyID, err := contracts.KeyID(observerPublic)
	if err != nil {
		return contracts.ObserverTrustRootV1{}, nil, err
	}
	root := contracts.ObserverTrustRootV1{
		SchemaVersion: "agmind.observer-trust-root.v1",
		HostID:        hostID,
		KeyID:         keyID,
		KeyEpoch:      1,
		PublicKey:     hex.EncodeToString(observerPublic),
	}
	if err := root.Validate(); err != nil {
		return contracts.ObserverTrustRootV1{}, nil, err
	}
	raw, err := contracts.CanonicalJSON(root)
	if err != nil {
		return contracts.ObserverTrustRootV1{}, nil, err
	}
	return root, raw, nil
}

func validateTrustRoot(raw []byte) (contracts.ObserverTrustRootV1, error) {
	root, err := contracts.DecodeStrict[contracts.ObserverTrustRootV1](
		bytes.NewReader(raw),
		maxTrustRootBytes,
	)
	if err != nil {
		return contracts.ObserverTrustRootV1{}, fmt.Errorf("invalid observer trust root: %w", err)
	}
	canonical, err := contracts.CanonicalJSON(root)
	if err != nil || !bytes.Equal(raw, canonical) {
		return contracts.ObserverTrustRootV1{}, fmt.Errorf("observer trust root is not canonical JSON")
	}
	return root, nil
}

func tokenValue(raw []byte, label string) ([]byte, error) {
	value := raw
	if bytes.HasSuffix(value, []byte("\n")) {
		value = value[:len(value)-1]
		if bytes.HasSuffix(value, []byte("\r")) {
			value = value[:len(value)-1]
		}
	}
	if len(value) < 1 || len(value) > maxTokenBytes {
		return nil, fmt.Errorf("%s must contain a bounded token", label)
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return nil, fmt.Errorf("%s must contain only printable ASCII", label)
		}
	}
	return append([]byte(nil), value...), nil
}

func generateToken() ([]byte, error) {
	random := make([]byte, generatedTokenBytes)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return nil, fmt.Errorf("generate API token: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(random)
	return []byte(encoded + "\n"), nil
}

func readDGXTokenSource(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := durablefile.ReadTrustedRoot(
		path,
		maxTokenBytes+1,
		0o400,
		0o440,
		0o600,
		0o640,
	)
	if err != nil {
		return nil, fmt.Errorf("DGX token source is unsafe or unreadable: %w", err)
	}
	value, err := tokenValue(raw, "DGX token source")
	if err != nil {
		return nil, err
	}
	return append(value, '\n'), nil
}

func publishExpected(
	spec artifactSpec,
	state artifactState,
	expected []byte,
) (string, error) {
	if state.present {
		if !bytes.Equal(state.raw, expected) {
			return "", fmt.Errorf("%s conflicts with the expected installation identity", spec.name)
		}
		return "preserved", nil
	}
	if err := durablefile.CreateOnly(spec.path, expected); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("create %s: %w", spec.name, err)
		}
		raced, readErr := readArtifact(spec)
		if readErr != nil || !raced.present || !bytes.Equal(raced.raw, expected) {
			return "", fmt.Errorf("%s was created concurrently with conflicting content", spec.name)
		}
		return "preserved", nil
	}
	created, err := readArtifact(spec)
	if err != nil || !created.present || !bytes.Equal(created.raw, expected) {
		return "", fmt.Errorf("created %s failed trusted read-back", spec.name)
	}
	return "created", nil
}

func initialize(dgxSourcePath string) (bootstrapResultV1, error) {
	states, err := readAllArtifacts()
	if err != nil {
		return bootstrapResultV1{}, err
	}
	dgxSource, err := readDGXTokenSource(dgxSourcePath)
	if err != nil {
		return bootstrapResultV1{}, err
	}

	hostState := states[hostIDArtifact.name]
	observerKeyState := states[observerKeyArtifact.name]
	trustState := states[observerTrustArtifact.name]
	actuatorKeyState := states[actuatorKeyArtifact.name]
	actuatorPublicState := states[actuatorPublicArtifact.name]

	if trustState.present && (!hostState.present || !observerKeyState.present) {
		return bootstrapResultV1{}, fmt.Errorf("unsafe partial observer identity")
	}
	if actuatorPublicState.present && !actuatorKeyState.present {
		return bootstrapResultV1{}, fmt.Errorf("unsafe partial actuator identity")
	}

	var hostID string
	var hostPayload []byte
	if hostState.present {
		hostID, err = parseHostID(hostState.raw)
		hostPayload = hostState.raw
	} else {
		hostID, err = generateHostID()
		hostPayload = []byte(hostID + "\n")
	}
	if err != nil {
		return bootstrapResultV1{}, err
	}

	var observerPrivate ed25519.PrivateKey
	if observerKeyState.present {
		observerPrivate, err = validatePrivateKey(observerKeyState.raw, "observer private key")
	} else {
		observerPrivate, err = generatePrivateKey("observer private key")
	}
	if err != nil {
		return bootstrapResultV1{}, err
	}
	observerPublic := publicKey(observerPrivate)
	expectedRoot, trustPayload, err := expectedTrustRoot(hostID, observerPublic)
	if err != nil {
		return bootstrapResultV1{}, err
	}
	if trustState.present {
		existingRoot, rootErr := validateTrustRoot(trustState.raw)
		if rootErr != nil {
			return bootstrapResultV1{}, rootErr
		}
		if existingRoot != expectedRoot {
			return bootstrapResultV1{}, fmt.Errorf("observer trust root does not bind the host and private key")
		}
		trustPayload = trustState.raw
	}

	var actuatorPrivate ed25519.PrivateKey
	if actuatorKeyState.present {
		actuatorPrivate, err = validatePrivateKey(actuatorKeyState.raw, "actuator private key")
	} else {
		actuatorPrivate, err = generatePrivateKey("actuator private key")
	}
	if err != nil {
		return bootstrapResultV1{}, err
	}
	actuatorPublic := publicKey(actuatorPrivate)
	if actuatorPublicState.present && !bytes.Equal(actuatorPublicState.raw, actuatorPublic) {
		return bootstrapResultV1{}, fmt.Errorf("actuator public key does not bind the private key")
	}

	coreTokenState := states[coreTokenArtifact.name]
	var coreTokenPayload []byte
	if coreTokenState.present {
		if _, err := tokenValue(coreTokenState.raw, "Core API token"); err != nil {
			return bootstrapResultV1{}, err
		}
		coreTokenPayload = coreTokenState.raw
	} else {
		coreTokenPayload, err = generateToken()
		if err != nil {
			return bootstrapResultV1{}, err
		}
	}

	dgxTokenState := states[dgxTokenArtifact.name]
	var dgxTokenPayload []byte
	if dgxTokenState.present {
		existingToken, tokenErr := tokenValue(dgxTokenState.raw, "DGX API token")
		if tokenErr != nil {
			return bootstrapResultV1{}, tokenErr
		}
		if dgxSource != nil {
			sourceToken, sourceErr := tokenValue(dgxSource, "DGX token source")
			if sourceErr != nil {
				return bootstrapResultV1{}, sourceErr
			}
			if len(existingToken) != len(sourceToken) ||
				subtle.ConstantTimeCompare(existingToken, sourceToken) != 1 {
				return bootstrapResultV1{}, fmt.Errorf("DGX API token conflicts with the supplied source")
			}
		}
		dgxTokenPayload = dgxTokenState.raw
	} else if dgxSource != nil {
		dgxTokenPayload = dgxSource
	} else {
		dgxTokenPayload, err = generateToken()
		if err != nil {
			return bootstrapResultV1{}, err
		}
	}

	statuses := make(map[string]string, 7)
	publications := []struct {
		spec    artifactSpec
		state   artifactState
		payload []byte
	}{
		{hostIDArtifact, hostState, hostPayload},
		{observerKeyArtifact, observerKeyState, observerPrivate},
		{observerTrustArtifact, trustState, trustPayload},
		{actuatorKeyArtifact, actuatorKeyState, actuatorPrivate},
		{actuatorPublicArtifact, actuatorPublicState, actuatorPublic},
		{coreTokenArtifact, coreTokenState, coreTokenPayload},
		{dgxTokenArtifact, dgxTokenState, dgxTokenPayload},
	}
	for _, publication := range publications {
		status, publishErr := publishExpected(
			publication.spec,
			publication.state,
			publication.payload,
		)
		if publishErr != nil {
			return bootstrapResultV1{}, publishErr
		}
		statuses[publication.spec.name] = status
	}

	actuatorKeyID, err := contracts.KeyID(actuatorPublic)
	if err != nil {
		return bootstrapResultV1{}, err
	}
	return bootstrapResultV1{
		SchemaVersion: "agmind.bootstrap-result.v1",
		HostID:        hostID,
		ObserverKeyID: expectedRoot.KeyID,
		ActuatorKeyID: actuatorKeyID,
		Artifacts:     statuses,
	}, nil
}

func parseArguments(args []string) (string, error) {
	if len(args) < 1 || args[0] != "init" {
		return "", fmt.Errorf("usage: agmind-bootstrap init [--dgx-token-file PATH]")
	}
	flags := flag.NewFlagSet("agmind-bootstrap init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var dgxSourcePath string
	flags.StringVar(&dgxSourcePath, "dgx-token-file", "", "")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return "", fmt.Errorf("usage: agmind-bootstrap init [--dgx-token-file PATH]")
	}
	return dgxSourcePath, nil
}

func run(args []string, stdout io.Writer) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("agmind-bootstrap is supported only on Linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("agmind-bootstrap requires EUID 0")
	}
	dgxSourcePath, err := parseArguments(args)
	if err != nil {
		return err
	}
	result, err := initialize(dgxSourcePath)
	if err != nil {
		return err
	}
	payload, err := contracts.CanonicalJSON(result)
	if err != nil {
		return fmt.Errorf("encode non-secret result: %w", err)
	}
	if _, err := stdout.Write(payload); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "agmind-bootstrap:", err)
		os.Exit(1)
	}
}
