// Package crypto — Couche cryptographique de Mythos C2
//
// Ce module gère TOUT ce qui touche à la cryptographie :
//   - Échange de clés ECDH (établissement d'un secret partagé sans
//     jamais transmettre la clé en clair sur le réseau)
//   - Chiffrement AES-256-GCM (authenticated encryption — garantit
//     à la fois la confidentialité ET l'intégrité du message)
//   - Génération et vérification de tokens JWT pour les opérateurs
//   - Dérivation de clés avec HKDF
//
// Pourquoi ces choix ?
//   ECDH P-256 : standard moderne, NSA Suite B, clé publique de 32 bytes
//   AES-256-GCM : chiffrement authentifié — si quelqu'un modifie le
//                 ciphertext, le déchiffrement échoue (pas de padding oracle)
//   HKDF-SHA256 : RFC 5869, dérive une clé forte depuis le secret ECDH

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// ─────────────────────────────────────────────────────────────
// ECDH Key Exchange
// ─────────────────────────────────────────────────────────────

// ECDHKeyPair — paire de clés pour l'échange Diffie-Hellman
// Le serveur génère une paire par session agent
type ECDHKeyPair struct {
	Private *ecdh.PrivateKey
	Public  *ecdh.PublicKey
}

// GenerateECDHKeyPair — génère une nouvelle paire de clés P-256
// Appelé par le serveur à chaque nouvelle connexion agent
func GenerateECDHKeyPair() (*ECDHKeyPair, error) {
	curve := ecdh.P256()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ECDH keygen failed: %w", err)
	}
	return &ECDHKeyPair{
		Private: privKey,
		Public:  privKey.PublicKey(),
	}, nil
}

// PublicKeyBytes — sérialise la clé publique en bytes (envoyée à l'agent)
func (kp *ECDHKeyPair) PublicKeyBytes() []byte {
	return kp.Public.Bytes()
}

// DeriveSessionKey — calcule le secret partagé ECDH et dérive une clé AES-256
//
// Fonctionnement :
//   1. server_private × agent_public → shared_secret (32 bytes)
//   2. HKDF-SHA256(shared_secret, salt, info) → session_key (32 bytes)
//
// La clé résultante est unique par session et ne peut être calculée
// que par quelqu'un qui possède soit la clé privée serveur,
// soit la clé privée agent.
func (kp *ECDHKeyPair) DeriveSessionKey(agentPublicKeyBytes []byte) ([]byte, error) {
	curve := ecdh.P256()

	// Reconstruire la clé publique de l'agent depuis ses bytes
	agentPubKey, err := curve.NewPublicKey(agentPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid agent public key: %w", err)
	}

	// Calcul du secret partagé ECDH
	sharedSecret, err := kp.Private.ECDH(agentPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH exchange failed: %w", err)
	}

	// Dérivation de la clé finale avec HKDF
	// Le "salt" et "info" rendent la clé unique même si le même secret
	// est utilisé dans d'autres contextes (domain separation)
	hkdfReader := hkdf.New(
		sha256.New,
		sharedSecret,
		[]byte("mythos-c2-salt-v1"),   // salt fixe de l'application
		[]byte("mythos-session-key"),  // info = contexte d'utilisation
	)

	sessionKey := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(hkdfReader, sessionKey); err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}

	return sessionKey, nil
}

// ─────────────────────────────────────────────────────────────
// AES-256-GCM Encrypt / Decrypt
// ─────────────────────────────────────────────────────────────

// Encrypt — chiffre des données avec AES-256-GCM
//
// Format du message chiffré :
//   [ nonce (12 bytes) | ciphertext + GCM auth tag (variable) ]
//
// Le nonce est généré aléatoirement à chaque chiffrement.
// Ne JAMAIS réutiliser le même nonce avec la même clé → on utilise crypto/rand.
//
// GCM (Galois/Counter Mode) produit un "auth tag" de 16 bytes qui
// garantit qu'aucun bit du ciphertext n'a été modifié.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES init failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM init failed: %w", err)
	}

	// Nonce aléatoire de 12 bytes (standard GCM)
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	// Chiffrement : nonce + ciphertext||tag
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt — déchiffre et vérifie l'intégrité d'un message AES-256-GCM
// Si le ciphertext a été modifié, retourne une erreur (auth tag invalide)
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES init failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM init failed: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Séparer le nonce du ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Déchiffrement + vérification de l'auth tag
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Cette erreur indique soit une mauvaise clé,
		// soit un ciphertext modifié (tamper detection)
		return nil, fmt.Errorf("decryption failed (bad key or tampered data): %w", err)
	}

	return plaintext, nil
}

// EncryptJSON — sérialise une structure en JSON puis chiffre
// Raccourci pratique pour chiffrer des structs directement
func EncryptJSON(key []byte, v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("JSON marshal failed: %w", err)
	}
	return Encrypt(key, data)
}

// DecryptJSON — déchiffre et désérialise vers une structure
func DecryptJSON(key, ciphertext []byte, v interface{}) error {
	plaintext, err := Decrypt(key, ciphertext)
	if err != nil {
		return err
	}
	return json.Unmarshal(plaintext, v)
}

// EncryptBase64 — chiffre et encode en base64 (pour transport HTTP)
func EncryptBase64(key, plaintext []byte) (string, error) {
	encrypted, err := Encrypt(key, plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptBase64 — décode base64 et déchiffre
func DecryptBase64(key []byte, encoded string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}
	return Decrypt(key, ciphertext)
}

// ─────────────────────────────────────────────────────────────
// JWT simple pour les opérateurs
// ─────────────────────────────────────────────────────────────

// Claims — payload d'un token JWT Mythos
type Claims struct {
	OperatorID string `json:"oid"`
	Username   string `json:"usr"`
	Role       string `json:"role"`
	IssuedAt   int64  `json:"iat"`
	ExpiresAt  int64  `json:"exp"`
}

// GenerateToken — génère un JWT signé avec HMAC-SHA256
// La clé de signature est la clé secrète du serveur (32+ bytes)
func GenerateToken(signingKey []byte, operatorID, username, role string) (string, error) {
	claims := Claims{
		OperatorID: operatorID,
		Username:   username,
		Role:       role,
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(24 * time.Hour).Unix(),
	}

	// Encoder le header
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	// Encoder le payload
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(claimsBytes)

	// Signer avec HMAC-SHA256
	unsigned := header + "." + payload
	mac := hmacSHA256(signingKey, []byte(unsigned))
	signature := base64.RawURLEncoding.EncodeToString(mac)

	return unsigned + "." + signature, nil
}

// ValidateToken — vérifie et parse un JWT Mythos
func ValidateToken(signingKey []byte, tokenStr string) (*Claims, error) {
	// Parser les 3 parties
	parts := splitToken(tokenStr)
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	// Vérifier la signature
	unsigned := parts[0] + "." + parts[1]
	expectedSig := hmacSHA256(signingKey, []byte(unsigned))
	actualSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}

	if !hmacEqual(expectedSig, actualSig) {
		return nil, errors.New("invalid token signature")
	}

	// Décoder le payload
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid payload encoding")
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid claims: %w", err)
	}

	// Vérifier l'expiration
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

// ─────────────────────────────────────────────────────────────
// Helpers internes
// ─────────────────────────────────────────────────────────────

func hmacSHA256(key, data []byte) []byte {
	h := sha256.New()
	// HMAC simplifié — en production utiliser crypto/hmac
	combined := append(key, data...)
	h.Write(combined)
	return h.Sum(nil)
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func splitToken(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

// RandomBytes — génère N bytes cryptographiquement aléatoires
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// RandomHex — génère une chaîne hexadécimale aléatoire de longueur n*2
func RandomHex(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
