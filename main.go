package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big" // Import for big.Int operations
	"net/http"
	"os"

	// "strconv" // Removed as no longer used
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5" // Recommended JWT library for Go
	"github.com/google/uuid"       // For generating UUIDs (kid, jti)
)

// Global variables for configuration
var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	jwksSet    JWKS
	keyID      string
	algorithm  string // e.g., RS256, RS512

	// JWT Claims configuration
	jwtIssuer   string
	jwtAudience string
	listenPort  string

	// Define PRIVATE_KEY_FILE as a global variable
	PRIVATE_KEY_FILE = "private_key.pem" // Default path for the private key
)

// JWKS represents the JSON Web Key Set structure
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key Type, e.g., "RSA"
	N   string `json:"n"`   // Modulus (Base64urlUInt-encoded)
	E   string `json:"e"`   // Exponent (Base64urlUInt-encoded)
	Kid string `json:"kid"` // Key ID
	Use string `json:"use"` // Key Usage, e.g., "sig"
	Alg string `json:"alg"` // Algorithm, e.g., "RS256"
}

// TokenRequest represents the expected payload for /token endpoint
type TokenRequest struct {
	Subject string `json:"sub"`
	Role    string `json:"role"` // Custom claim
	// Add any other custom claims your RouteAuthFilter needs
	Audience interface{} `json:"aud"` // Changed to interface{} to handle string or []string
	Issuer   string      `json:"iss"` // Optional: If client specifies issuer
	Exp      int64       `json:"exp"` // Optional: Expiration in seconds from now
	Nbf      int64       `json:"nbf"` // Optional: Not Before in seconds from now
}

// VerifyResponse represents the JSON response for the /verify-jwt endpoint
type VerifyResponse struct {
	IsValid   bool        `json:"isValid"`
	Message   string      `json:"message"`
	Header    interface{} `json:"header,omitempty"`
	Payload   interface{} `json:"payload,omitempty"`
	ExpiresAt string      `json:"expiresAt,omitempty"`
	IssuedAt  string      `json:"issuedAt,omitempty"`
	NotBefore string      `json:"notBefore,omitempty"`
	Error     string      `json:"error,omitempty"`
}

func init() {
	// Load configuration from environment variables
	jwtIssuer = os.Getenv("JWT_ISSUER")
	if jwtIssuer == "" {
		jwtIssuer = "https://my-go-issuer.example.com" // Default issuer
	}
	jwtAudience = os.Getenv("JWT_AUDIENCE")
	if jwtAudience == "" {
		jwtAudience = "your-api-audience" // Default audience
	}
	listenPort = os.Getenv("LISTEN_PORT")
	if listenPort == "" {
		listenPort = "8080" // Default listen port
	}

	keyID = os.Getenv("JWKS_KID")
	if keyID == "" {
		keyID = uuid.New().String() // Generate new KID if not set
	}
	algorithm = os.Getenv("JWKS_ALG")
	if algorithm == "" {
		algorithm = "RS512" // Default algorithm
	}
}

// generateKeys generates a new RSA key pair and saves them to files.
func generateKeys(privateKeyFile, publicKeyFile string) {
	log.Println("--- Generating 2048-bit RSA key pair... ---")
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatalf("Failed to generate private key: %v", err)
	}
	publicKey = &privateKey.PublicKey
	log.Println("Key pair generated.")

	// Save private key to PEM
	privatePEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := os.WriteFile(privateKeyFile, pem.EncodeToMemory(privatePEM), 0600); err != nil {
		fatalf("Failed to write private key: %v", err)
	}
	log.Printf("Private key saved to %s", privateKeyFile)

	// Save public key to PEM
	publicASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fatalf("Failed to marshal public key: %v", err)
	}
	publicPEM := &pem.Block{
		Type:  "PUBLIC KEY", // Use "PUBLIC KEY" for PKIX, not "RSA PUBLIC KEY" for PKCS1
		Bytes: publicASN1,
	}
	if err := os.WriteFile(publicKeyFile, pem.EncodeToMemory(publicPEM), 0644); err != nil {
		fatalf("Failed to write public key: %v", err)
	}
	log.Printf("Public key saved to %s", publicKeyFile)

	// Generate JWKS
	generateJWKS()
}

// generateJWKS populates the global jwksSet using the loaded publicKey.
func generateJWKS() {
	if publicKey == nil {
		fatal("Public key not loaded, cannot generate JWKS.")
	}

	// Convert public key to JWK components
	// Use RawURLEncoding as per JWK spec
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())

	// Fix: Convert publicKey.E (int) to *big.Int before passing to bigIntToBytes
	eBigInt := big.NewInt(int64(publicKey.E))
	e := base64.RawURLEncoding.EncodeToString(bigIntToBytes(eBigInt))

	jwk := JWK{
		Kty: "RSA",
		N:   n,
		E:   e,
		Kid: keyID,
		Use: "sig",
		Alg: algorithm,
	}
	jwksSet = JWKS{Keys: []JWK{jwk}}

	jwksJSON, err := json.MarshalIndent(jwksSet, "", "  ")
	if err != nil {
		fatalf("Failed to marshal JWKS: %v", err)
	}
	log.Println("\n--- JWKS Public Key JSON (for review) ---")
	fmt.Println(string(jwksJSON))

	jwksBase64 := base64.StdEncoding.EncodeToString(jwksJSON)
	log.Println("\n--- BASE64-ENCODED JWKS STRING (Copy this for JWTProvider.jsonWebKeySet.local.jwks) ---")
	fmt.Println(jwksBase64)

	log.Printf("\n--- IMPORTANT: Note your KID: %s ---", keyID)
	log.Printf("--- IMPORTANT: Note your ALG: %s ---", algorithm)
	log.Printf("--- IMPORTANT: Note your ISSUER: %s ---", jwtIssuer)
	log.Printf("--- IMPORTANT: Note your AUDIENCE: %s ---", jwtAudience)
}

// loadPrivateKey loads an RSA private key from a PEM file.
func loadPrivateKey(privateKeyFile string) error {
	keyBytes, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Try parsing PKCS1 or PKCS8 private key
	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsedKey_pkcs8, err_pkcs8 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err_pkcs8 != nil {
			return fmt.Errorf("failed to parse private key: %v (PKCS1) / %v (PKCS8)", err, err_pkcs8)
		}
		var ok bool
		privateKey, ok = parsedKey_pkcs8.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key is not RSA: %T", parsedKey_pkcs8)
		}
	} else {
		privateKey = parsedKey
	}
	publicKey = &privateKey.PublicKey // Derive public key
	return nil
}

// bigIntToBytes converts a *big.Int to a byte slice suitable for base64url encoding.
// It handles leading zeros for Base64urlUInt as per RFC 7518 Section 6.3.1.1.
func bigIntToBytes(n *big.Int) []byte {
	b := n.Bytes()
	// Remove leading zero for positive numbers if present, as per RFC 7518 Section 6.3.1.1
	// for converting to Base64urlUInt.
	if len(b) > 0 && b[0] == 0 {
		return b[1:]
	}
	return b
}

// handleJWKS serves the JWKS JSON.
func handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwksSet); err != nil {
		http.Error(w, "Failed to encode JWKS", http.StatusInternalServerError)
		log.Printf("Error encoding JWKS: %v", err)
	}
}

// handleToken generates a JWT based on POST request claims.
func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	if privateKey == nil {
		http.Error(w, "Private key not loaded, cannot sign JWT", http.StatusInternalServerError)
		return
	}

	var req TokenRequest
	// Use json.NewDecoder for JSON body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON request body", http.StatusBadRequest)
		log.Printf("Invalid JSON request body: %v", err)
		return
	}

	// Prepare claims - use defaults from environment/init if not provided in request
	claims := jwt.MapClaims{}

	claims["sub"] = req.Subject // Subject is explicitly from request
	if claims["sub"] == "" {
		claims["sub"] = "default_user"
	}

	claims["iss"] = jwtIssuer // Use global issuer as default
	if req.Issuer != "" {
		claims["iss"] = req.Issuer // Override if provided in request
	}

	claims["aud"] = []string{jwtAudience} // Use global audience as default (as array)
	if req.Audience != nil {
		if audStr, ok := req.Audience.(string); ok && audStr != "" {
			claims["aud"] = []string{audStr}
		} else if audList, ok := req.Audience.([]interface{}); ok { // Handle array audience
			var auds []string
			for _, a := range audList {
				if s, ok := a.(string); ok {
					auds = append(auds, s)
				}
			}
			if len(auds) > 0 {
				claims["aud"] = auds
			}
		}
	}

	claims["iat"] = time.Now().Unix()
	claims["jti"] = uuid.New().String()

	if req.Nbf != 0 {
		claims["nbf"] = req.Nbf
	} else {
		claims["nbf"] = claims["iat"]
	}
	if req.Exp != 0 {
		claims["exp"] = req.Exp
	} else {
		claims["exp"] = claims["iat"].(int64) + 3600 // Default to 1 hour expiration
	}

	if req.Role != "" {
		claims["role"] = req.Role
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.GetSigningMethod(algorithm), claims)
	token.Header["kid"] = keyID
	token.Header["alg"] = algorithm

	// Sign token
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		log.Printf("Error signing token: %v", err)
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"message":      "Successfully created token",
		"access_token": signedToken,
		"token_type":   "Bearer",
		"expires_in":   claims["exp"].(int64) - claims["iat"].(int64), // Remaining seconds
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode token response", http.StatusInternalServerError)
		log.Printf("Error encoding token response: %v", err)
	}
}

// handleVerifyJWT verifies a JWT and prints its contents.
func handleVerifyJWT(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := VerifyResponse{IsValid: false, Message: "Verification failed"}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		response.Message = "Authorization header missing"
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding response: %v", err)
		}
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader { // No "Bearer " prefix
		response.Message = "Token must be prefixed with 'Bearer '"
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding response: %v", err)
		}
		return
	}

	// Key lookup function for jwt.Parse
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Ensure algorithm matches
		if token.Header["alg"] != algorithm {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Ensure kid matches if present in token
		if kidFromToken, ok := token.Header["kid"].(string); ok && kidFromToken != keyID {
			return nil, fmt.Errorf("unexpected kid: %v", kidFromToken)
		}
		return publicKey, nil
	}

	token, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		response.Message = fmt.Sprintf("Token parsing/validation error: %v", err)
		response.Error = err.Error()
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding response: %v", err)
		}
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		response.IsValid = true
		response.Message = "Token is valid"
		response.Payload = claims
		response.Header = token.Header

		if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
			response.ExpiresAt = exp.Format(time.RFC3339) // Use RFC3339 for standard datetime format
		}
		if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
			response.IssuedAt = iat.Format(time.RFC3339)
		}
		if nbf, err := claims.GetNotBefore(); err == nil && nbf != nil {
			response.NotBefore = nbf.Format(time.RFC3339)
		}
	} else {
		response.Message = "Token is invalid or claims format is unexpected"
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// handleRefreshJWKS re-reads JWKS configuration (like KID/ALG from env vars)
// and regenerates the JWKS set.
func handleRefreshJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { // Typically a POST to trigger an action
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// Re-read environment variables for KID and ALG
	// This ensures that if the K8s deployment's ENV vars were updated,
	// the running app can pick them up without a full restart.
	newKeyID := os.Getenv("JWKS_KID")
	if newKeyID == "" {
		newKeyID = uuid.New().String() // Generate new if not set
	}
	newAlgorithm := os.Getenv("JWKS_ALG")
	if newAlgorithm == "" {
		newAlgorithm = "RS512" // Default algorithm
	}

	// Update global variables
	keyID = newKeyID
	algorithm = newAlgorithm

	// Regenerate JWKS based on current public key and potentially new KID/ALG
	log.Println("--- Refreshing JWKS based on current key and configuration ---")
	generateJWKS() // This function uses the updated global keyID and algorithm

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]string{"message": "JWKS refreshed successfully", "kid": keyID, "alg": algorithm}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode refresh response", http.StatusInternalServerError)
		log.Printf("Error encoding refresh response: %v", err)
	}
}

// Testable fatal error handlers
var fatalf = log.Fatalf
var fatal = log.Fatal

// main handles CLI commands or starts the HTTP server.
func main() {
	// Parse CLI arguments
	if len(os.Args) > 1 {
		command := os.Args[1]
		switch command {
		case "generate-keys":
			privateKeyFile := "private_key.pem"
			publicKeyFile := "public_key.pem"
			if len(os.Args) > 2 { // Allows specifying custom output file name for private key
				privateKeyFile = os.Args[2]
				publicKeyFile = privateKeyFile + ".pub" // Public key name derived from private key file
			}
			generateKeys(privateKeyFile, publicKeyFile)
			return
		case "generate-jwt":
			// Adjust argument parsing for optional payload string
			// Default private key file is used if not provided explicitly
			privateKeyFile := PRIVATE_KEY_FILE // Reference the global variable for default
			payloadStr := "{}"                 // Default empty payload

			// Determine if private key file path is explicitly provided
			if len(os.Args) >= 3 {
				if !strings.HasPrefix(os.Args[2], "{") && !strings.HasPrefix(os.Args[2], "[") {
					privateKeyFile = os.Args[2]
				} else {
					payloadStr = os.Args[2]
				}
			}
			if len(os.Args) >= 4 {
				payloadStr = os.Args[3]
			}
			if len(os.Args) > 4 {
				fatal("Usage: go run main.go generate-jwt [private_key_file] [payload_json_string]")
			}

			if err := loadPrivateKey(privateKeyFile); err != nil {
				fatalf("%v", err)
			}

			var customClaims map[string]interface{}
			if err := json.Unmarshal([]byte(payloadStr), &customClaims); err != nil {
				fatalf("Invalid payload JSON: %v", err)
			}

			// Prepare claims, using global defaults unless overridden by customClaims
			claims := jwt.MapClaims{
				"sub": "cli_user",            // Default subject for CLI
				"iss": jwtIssuer,             // Default issuer from global config
				"aud": []string{jwtAudience}, // Default audience from global config
				"iat": float64(time.Now().Unix()),
				"jti": uuid.New().String(),
				"nbf": float64(time.Now().Unix()),
				"exp": float64(time.Now().Unix()) + 3600, // 1 hour default expiration
			}

			// Override standard claims if provided in customClaims
			if sub, ok := customClaims["sub"].(string); ok && sub != "" {
				claims["sub"] = sub
			}
			if iss, ok := customClaims["iss"].(string); ok && iss != "" {
				claims["iss"] = iss
			}
			if aud, ok := customClaims["aud"].(string); ok && aud != "" { // Handle single string audience
				claims["aud"] = []string{aud}
			} else if audList, ok := customClaims["aud"].([]interface{}); ok { // Handle array audience
				var auds []string
				for _, a := range audList {
					if s, ok := a.(string); ok {
						auds = append(auds, s)
					}
				}
				if len(auds) > 0 {
					claims["aud"] = auds
				}
			}
			if iat, ok := customClaims["iat"].(float64); ok && iat != 0 {
				claims["iat"] = iat
			}
			if nbf, ok := customClaims["nbf"].(float64); ok && nbf != 0 {
				claims["nbf"] = nbf
			}
			if exp, ok := customClaims["exp"].(float64); ok && exp != 0 {
				claims["exp"] = exp
			}

			// Add other custom claims from customClaims
			for key, value := range customClaims {
				if key != "sub" && key != "iss" && key != "aud" && key != "iat" && key != "nbf" && key != "exp" && key != "jti" {
					claims[key] = value
				}
			}

			token := jwt.NewWithClaims(jwt.GetSigningMethod(algorithm), claims)
			token.Header["kid"] = keyID
			token.Header["alg"] = algorithm

			signedToken, err := token.SignedString(privateKey)
			if err != nil {
				fatalf("Failed to sign token: %v", err)
			}
			fmt.Println(signedToken)
			return
		default:
			log.Printf("Unknown command: %s. Starting HTTP server...", command)
		}
	}

	// HTTP server mode
	log.Println("Starting HTTP server...")
	if err := loadPrivateKey(PRIVATE_KEY_FILE); err != nil {
		fatalf("%v", err)
	}

	http.HandleFunc("/jwks", handleJWKS)
	http.HandleFunc("/token", handleToken)
	http.HandleFunc("/verify-jwt", handleVerifyJWT) // NEW: Verify JWT endpoint
	http.HandleFunc("/refresh-jwks", handleRefreshJWKS)

	log.Printf("Listening on :%s", listenPort)
	fatal(http.ListenAndServe(":"+listenPort, nil))
}
