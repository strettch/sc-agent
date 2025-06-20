package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"sync"
)

var (
	mu         sync.Mutex
	backendURL string = "https://cf37-2c0f-eb68-65a-ca00-4486-1923-f9cd-7add.ngrok-free.app/api/v1/"
)

func init() {
	fmt.Printf("[sc-agent] Using backend URL: %s\n", backendURL)
}

func main() {
	http.HandleFunc("/notify", notifyHandler)

	fmt.Println("[sc-agent] Listening for notifications on :60500")
	err := http.ListenAndServe(":60500", nil)
	if err != nil {
		fmt.Printf("[sc-agent] Server error: %v\n", err)
	}
}

type notifyPayload struct {
	SessionID string `json:"session_id"`
}

func notifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload notifyPayload
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(body, &payload)
	if err != nil || payload.SessionID == "" {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	fmt.Printf("[sc-agent] Received notification for Session ID: %s\n", payload.SessionID)

	// Lock to prevent concurrent key installs for same session
	mu.Lock()
	defer mu.Unlock()

	// 1. Fetch public key from resource manager
	publicKey, err := fetchPublicKeyFromResourceManager(payload.SessionID)
	if err != nil {
		fmt.Printf("[sc-agent] Error fetching public key: %v\n", err)
		http.Error(w, "Failed to fetch public key", http.StatusInternalServerError)
		return
	}

	// 2. Install public key
	err = installPublicKey(publicKey)
	if err != nil {
		fmt.Printf("[sc-agent] Error installing key: %v\n", err)
		http.Error(w, "Failed to install key", http.StatusInternalServerError)
		return
	}

	// 3. Notify resource manager (or set flag in Redis)
	err = confirmKeyInstalled(payload.SessionID)
	if err != nil {
		fmt.Printf("[sc-agent] Error confirming key install: %v\n", err)
		http.Error(w, "Failed to confirm key install", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Key installed"))
}

func fetchPublicKeyFromResourceManager(sessionID string) (string, error) {
	// TODO: Make resource manager URL configurable
	url := fmt.Sprintf("https://cf37-2c0f-eb68-65a-ca00-4486-1923-f9cd-7add.ngrok-free.app/api/v1/console/public-key?session_id=%s", sessionID)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resource manager returned status %d", resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var result struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	return result.PublicKey, nil
}

func confirmKeyInstalled(sessionID string) error {
	// TODO: Make resource manager Redis accessible or provide a callback endpoint
	// For now, assume Redis is accessible and set a flag
	// In production, you may want to POST to a callback endpoint
	// This is a placeholder
	return nil
}

func installPublicKey(pubKey string) error {
	userInfo, err := user.Current()
	if err != nil {
		return err
	}

	sshDir := filepath.Join(userInfo.HomeDir, ".ssh")
	authKeysPath := filepath.Join(sshDir, "authorized_keys")

	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh dir: %w", err)
	}

	f, err := os.OpenFile(authKeysPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open authorized_keys: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(pubKey + "\n"); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	fmt.Println("[sc-agent] ✅ Key installed.")
	return nil
}
