package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/Nerzal/gocloak"
)

var (
	clientID     = "sso"
	clientSecret = "X8vL8Y82R5oZemdyQjxvKD60dBtGvZrH"
	realm        = "master"
	frontend     = "https://localhost/index2.html"
	keycloakURL  = "http://localhost:8090/auth"
	callbackURL  = "http://localhost:8000/callback"
	grantType    = "authorization_code"
)

func main() {

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/logout", logoutHandler)

	log.Println("Starting Keycloak SSO server on :8000...")
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Yönlendirme URL'si için kullanıcıyı Keycloak kimlik doğrulama sayfasına yönlendirme
	authorizationURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth?client_id=%s&redirect_uri=%s&response_type=code", keycloakURL, realm, clientID, callbackURL)
	http.Redirect(w, r, authorizationURL, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	keycloakClient := gocloak.NewClient("http://localhost:8090/auth")

	// Kimlik doğrulama sonrası Keycloak callback URL'inden dönen kodu alıyoruz
	code := r.URL.Query().Get("code")
	fmt.Print("code:", code)
	// Alınan kodu kullanarak token alıyoruz
	ctx := context.Background()
	token, err := keycloakClient.GetToken(ctx, realm, gocloak.TokenOptions{

		ClientID:     &clientID,
		Code:         &code,
		ClientSecret: &clientSecret,
		GrantType:    &grantType,
		RedirectURI:  &callbackURL,
	})

	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, "Kimlik doğrulama hatası", http.StatusInternalServerError)
		return
	}

	// Token bilgilerini kullanarak kullanıcı adını alıyoruz
	userInfo, err := keycloakClient.GetUserInfo(ctx, token.AccessToken, "master")
	if err != nil {
		http.Error(w, "Kullanıcı bilgileri alınamadı", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, frontend+"?username="+*userInfo.PreferredUsername, http.StatusFound)
	// Kullanıcı adını gösteriyoruz
	w.Write([]byte("Kullanıcı Adı: " + *userInfo.PreferredUsername))
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	//http.Redirect(w, r, keycloakClient.GetLogoutURL("http://localhost:8000", realm), http.StatusFound)
}
