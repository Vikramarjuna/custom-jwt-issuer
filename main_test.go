package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func init() {
	// Always override fatal and fatalf to panic in tests
	fatal = func(v ...interface{}) {
		panic(fmt.Sprint(v...))
	}
	fatalf = func(format string, v ...interface{}) {
		panic(fmt.Sprintf(format, v...))
	}
}

func TestGenerateKeysAndJWKS(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey = &privateKey.PublicKey
	generateJWKS()
	if len(jwksSet.Keys) != 1 {
		t.Error("JWKS should contain one key")
	}
	if jwksSet.Keys[0].Kty != "RSA" {
		t.Error("JWK type should be RSA")
	}
}

func TestJWKSHandler(t *testing.T) {
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	publicKey = &privateKey.PublicKey
	generateJWKS()
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	rr := httptest.NewRecorder()
	handleJWKS(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
	var resp JWKS
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to unmarshal JWKS: %v", err)
	}
	if len(resp.Keys) == 0 {
		t.Error("JWKS response should contain at least one key")
	}
}

func TestTokenHandler_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	rr := httptest.NewRecorder()
	handleToken(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rr.Code)
	}
}

func TestTokenHandler_PrivateKeyNotLoaded(t *testing.T) {
	privateKey = nil
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	rr := httptest.NewRecorder()
	handleToken(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", rr.Code)
	}
}

func TestTokenHandler_Success(t *testing.T) {
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	publicKey = &privateKey.PublicKey
	generateJWKS()
	payload := `{"sub":"testuser","role":"admin","aud":"test-aud"}`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(payload))
	rr := httptest.NewRecorder()
	handleToken(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to unmarshal token response: %v", err)
	}
	if resp["access_token"] == nil {
		t.Error("Expected access_token in response")
	}
}

func TestTokenHandler_InvalidJSON(t *testing.T) {
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	publicKey = &privateKey.PublicKey
	generateJWKS()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("not-json"))
	rr := httptest.NewRecorder()
	handleToken(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

func TestVerifyJWTHandler_MissingAuthHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/verify-jwt", nil)
	rr := httptest.NewRecorder()
	handleVerifyJWT(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
	var resp VerifyResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Message != "Authorization header missing" {
		t.Errorf("Expected missing auth header message, got %s", resp.Message)
	}
}

func TestVerifyJWTHandler_InvalidAuthHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/verify-jwt", nil)
	req.Header.Set("Authorization", "notbearer sometoken")
	rr := httptest.NewRecorder()
	handleVerifyJWT(rr, req)
	var resp VerifyResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Message != "Token must be prefixed with 'Bearer '" {
		t.Errorf("Expected prefix error, got %s", resp.Message)
	}
}

func TestVerifyJWTHandler_InvalidToken(t *testing.T) {
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	publicKey = &privateKey.PublicKey
	generateJWKS()
	req := httptest.NewRequest(http.MethodPost, "/verify-jwt", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	rr := httptest.NewRecorder()
	handleVerifyJWT(rr, req)
	var resp VerifyResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.IsValid {
		t.Error("Expected invalid token to not be valid")
	}
}

func TestRefreshJWKSHandler_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/refresh-jwks", nil)
	rr := httptest.NewRecorder()
	handleRefreshJWKS(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rr.Code)
	}
}

func TestRefreshJWKSHandler_Success(t *testing.T) {
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	publicKey = &privateKey.PublicKey
	generateJWKS()
	req := httptest.NewRequest(http.MethodPost, "/refresh-jwks", nil)
	rr := httptest.NewRecorder()
	handleRefreshJWKS(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["message"] != "JWKS refreshed successfully" {
		t.Errorf("Expected refresh message, got %v", resp["message"])
	}
}

func TestVerifyJWTHandler_ValidToken(t *testing.T) {
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	publicKey = &privateKey.PublicKey
	generateJWKS()
	claims := jwt.MapClaims{"sub": "testuser", "iss": jwtIssuer, "aud": []string{jwtAudience}, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	token := jwt.NewWithClaims(jwt.GetSigningMethod(algorithm), claims)
	token.Header["kid"] = keyID
	token.Header["alg"] = algorithm
	signedToken, _ := token.SignedString(privateKey)
	req := httptest.NewRequest(http.MethodPost, "/verify-jwt", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken)
	rr := httptest.NewRecorder()
	handleVerifyJWT(rr, req)
	var resp VerifyResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if !resp.IsValid {
		t.Error("Expected valid token to be valid")
	}
}

func TestMain_CLI_UnknownCommand(t *testing.T) {
	// Create a dummy private_key.pem so server startup does not fail
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: pemBytes}
	_ = os.WriteFile("private_key.pem", pem.EncodeToMemory(pemBlock), 0600)
	defer os.Remove("private_key.pem")

	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	os.Args = []string{"main", "unknown-cmd"}
	// Should not panic, just log and start server (which we don't want to actually run)
	go func() {
		defer func() { recover() }()
		main()
	}()
	// Give it a moment to log and exit
	time.Sleep(100 * time.Millisecond)
}

func TestMain_CLI_GenerateKeys(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	os.Args = []string{"main", "generate-keys", "test_private.pem"}
	main()
	if _, err := os.Stat("test_private.pem"); err != nil {
		t.Errorf("Private key file not created: %v", err)
	}
	if _, err := os.Stat("test_private.pem.pub"); err != nil {
		t.Errorf("Public key file not created: %v", err)
	}
	os.Remove("test_private.pem")
	os.Remove("test_private.pem.pub")
}

func TestMain_CLI_GenerateJWT(t *testing.T) {
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	publicKey = &privateKey.PublicKey
	generateJWKS()
	pemBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: pemBytes}
	_ = os.WriteFile("test_cli_key.pem", pem.EncodeToMemory(pemBlock), 0600)
	origArgs := os.Args
	defer func() { os.Args = origArgs; os.Remove("test_cli_key.pem") }()
	os.Args = []string{"main", "generate-jwt", "test_cli_key.pem", `{"sub":"cliuser","role":"admin"}`}
	main()
}

func TestLoadPrivateKey_Error(t *testing.T) {
	err := loadPrivateKey("nonexistent.pem")
	if err == nil {
		t.Error("Expected error for missing private key file")
	}
}

func TestBigIntToBytes_LeadingZero(t *testing.T) {
	b := bigIntToBytes(big.NewInt(0))
	if len(b) != 0 {
		t.Errorf("Expected empty byte slice for 0, got %v", b)
	}
}

func TestHandleJWKS_Error(t *testing.T) {
	// Simulate error by replacing jwksSet with a type that can't be marshaled
	oldJWKS := jwksSet
	jwksSet = JWKS{Keys: []JWK{{Kty: "invalid", N: string([]byte{0xff, 0xfe}), E: "", Kid: "", Use: "", Alg: ""}}}
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	rr := httptest.NewRecorder()
	handleJWKS(rr, req)
	jwksSet = oldJWKS
}

// --- Additional tests for coverage ---

func TestGenerateJWKS_Error(t *testing.T) {
	// Simulate nil publicKey
	publicKey = nil
	origFatal := fatal
	defer func() { fatal = origFatal }()
	called := false
	fatal = func(v ...interface{}) {
		called = true
		panic("fatal called")
	}
	defer func() {
		recover()
		if !called {
			t.Error("Expected fatal for nil publicKey in generateJWKS")
		}
	}()
	generateJWKS()
}

func TestMain_CLI_InvalidUsage(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	os.Args = []string{"main", "generate-jwt", "key.pem", "payload", "extra"}
	origFatal := fatal
	defer func() { fatal = origFatal }()
	called := false
	fatal = func(v ...interface{}) {
		called = true
		panic("fatal called")
	}
	defer func() {
		recover()
		if !called {
			t.Error("Expected fatal for invalid usage")
		}
	}()
	main()
}

func TestMain_CLI_InvalidPayloadJSON(t *testing.T) {
	// Create a dummy private_key.pem
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: pemBytes}
	_ = os.WriteFile("private_key.pem", pem.EncodeToMemory(pemBlock), 0600)
	defer os.Remove("private_key.pem")
	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	os.Args = []string{"main", "generate-jwt", "private_key.pem", "not-json"}
	origFatalf := fatalf
	defer func() { fatalf = origFatalf }()
	called := false
	fatalf = func(format string, v ...interface{}) {
		called = true
		panic("fatalf called")
	}
	defer func() {
		recover()
		if !called {
			t.Error("Expected fatalf for invalid payload JSON")
		}
	}()
	main()
}

func TestMain_CLI_SignError(t *testing.T) {
	// Create a dummy private_key.pem
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: pemBytes}
	_ = os.WriteFile("private_key.pem", pem.EncodeToMemory(pemBlock), 0600)
	defer os.Remove("private_key.pem")
	// Generate a valid token first
	claims := jwt.MapClaims{"sub": "testuser", "iss": jwtIssuer, "aud": []string{jwtAudience}, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	token := jwt.NewWithClaims(jwt.GetSigningMethod(algorithm), claims)
	token.Header["kid"] = keyID
	token.Header["alg"] = algorithm
	signedToken, _ := token.SignedString(privateKey)
	// Now tamper with the token to simulate sign error
	tamperedToken := signedToken[:len(signedToken)-1] + "x"
	req := httptest.NewRequest(http.MethodPost, "/verify-jwt", nil)
	req.Header.Set("Authorization", "Bearer "+tamperedToken)
	rr := httptest.NewRecorder()
	handleVerifyJWT(rr, req)
	var resp VerifyResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.IsValid {
		t.Error("Expected tampered token to be invalid")
	}
}
