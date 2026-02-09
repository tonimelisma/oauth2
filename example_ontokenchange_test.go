// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"golang.org/x/oauth2"
)

// saveToken saves the token to a file as JSON.
func saveToken(tok *oauth2.Token) {
	data, err := json.Marshal(tok)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("token.json", data, 0600); err != nil {
		log.Fatal(err)
	}
}

// loadToken reads a previously saved token from a file.
func loadToken() (*oauth2.Token, error) {
	data, err := os.ReadFile("token.json")
	if err != nil {
		return nil, err
	}
	tok := new(oauth2.Token)
	return tok, json.Unmarshal(data, tok)
}

// doInitialOAuthFlow performs the initial authorization code exchange.
func doInitialOAuthFlow(ctx context.Context, conf *oauth2.Config) *oauth2.Token {
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
	fmt.Printf("Visit the URL for the auth dialog: %v\n", url)
	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatal(err)
	}
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		log.Fatal(err)
	}
	return tok
}

// This example demonstrates persisting tokens across process restarts.
// Any HTTP call may trigger a transparent token refresh, which may
// rotate both the access and refresh tokens. OnTokenChange is called
// when this happens, allowing the application to save the new token.
// On the next startup, the saved token is loaded — if the access
// token is still valid, no refresh is needed.
func ExampleConfig_onTokenChange() {
	ctx := context.Background()
	conf := &oauth2.Config{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		Scopes:       []string{"SCOPE1", "SCOPE2"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://provider.com/o/oauth2/auth",
			TokenURL: "https://provider.com/o/oauth2/token",
		},
		OnTokenChange: func(tok *oauth2.Token) {
			// Fired when a refresh produces a new token.
			// Persist the entire *Token (access token, refresh
			// token, expiry, etc.) to durable storage so it
			// survives process restarts.
			saveToken(tok)
		},
	}

	// On startup, try to load a previously saved token.
	tok, err := loadToken()
	if err != nil {
		// No saved token — run the initial OAuth flow to get one.
		tok = doInitialOAuthFlow(ctx, conf)
		saveToken(tok)
	}

	// If the loaded access token is still valid, it is used directly
	// with no refresh. When it eventually expires, the library
	// refreshes it transparently and OnTokenChange persists the
	// new token for next time.
	client := conf.Client(ctx, tok)
	client.Get("...")
}
