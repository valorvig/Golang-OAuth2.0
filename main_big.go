package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
)

type user struct {
	password []byte
	First    string
}

// don't create a new type but create a variable of that type
var oauth = &oauth2.Config{ // lets make it a pointer since every method requires the pointer
	ClientID:     "amzn1.application-oa2-client.de6b24d772514ec8bdfeed80484c115c",
	ClientSecret: "56fc6a7793fe0e8b5386c23a3c2ea1720d446079f24a99ce50f917430c555c33",
	// https://godoc.org/golang.org/x/oauth2/amazon#pkg-variables
	// the amazon endpoint will giveyou both AuthURl and TokenURL
	Endpoint: amazon.Endpoint, // Endpoint has AuthURL, TokenURL, and AuthStyle
	// RedirectURL is the URL to redirect users going through the OAuth flow, after the resource owner's URLs. after finished from the provider to our url next
	RedirectURL: "http://localhost:8080/oauth/amazon/receive", // we tell amazon's LWA in its setting page to redirect to this url
	/* Error Summary, 400 Bad Request, An unknown scope was requested*/
	// Scope specifies optional requested permissions. Can add many scopes.
	Scopes: []string{"profile"}, // amazon's LWA requires the Cusotmer Profile Info as the string "profile"
	// In the Web Settings from amazon developer, edit the Allowed Return URLs by putting our Redirect URL in it.
}

// key is email, and value is password
var db = map[string]user{
	/* rely on the user id, not the email which can be changed somewhere
	"test@example.com": user{
		First: "testFirstName", // test user
	},
	*/
}

// key is sessionid, value is email
var sessions = map[string]string{}

// key is uuid from oauth login, value is expiration time
var oauthExp = map[string]time.Time{}

// Maybe somebody has previously registered with this oauth2 provider with our site
// so get the local user ID from the oauthConnections map
// key is uuid from oauth provider; value is user id, e.g., email // in this case, we've used the email as the user id from the start
var oauthConnections = map[string]string{}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	// create an endpoint /oauth/<your provider>/login
	http.HandleFunc("/oauth/amazon/login", oAmazonlogin)
	// notice this is your "redirect" URL listed above in oauth2.Config
	// we decide the url "/oauth/amazon/receive" by ourselves
	http.HandleFunc("/oauth/amazon/receive", oAmazonReceive)
	// prefer to go all the way to partial register - don't want the user to hang around on and off the endpoint beacuase they don't lnow what oauth actually means
	http.HandleFunc("/partial-register", partialRegister)
	http.HandleFunc("/oauth/amazon/register", oAmazonRegister)
	http.HandleFunc("/logout", logout)
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("sessionID")
	if err != nil {
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
	}

	sID, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parsetoken", err)
	}

	// email
	var e string
	if sID != "" {
		e = sessions[sID] // get an email matched that session id
	}

	// first name
	var f string
	if user, ok := db[e]; ok {
		f = user.First
	}

	// func (r *Request) FormValue(key string) string
	// FormValue returns the first value for the named component of the query.
	errMsg := r.FormValue("msg")

	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta http-equiv="X-UA-Compatible" content="ie=edge">
		<title>Document</title>
	</head>
	<body>
		<h1>IF YOU HAVE A SESSION, HERE IS YOUR NAME: %s</h1>
		<h1>IF YOU HAVE A SESSION, HERE IS YOUR EMAIL: %s</h1>
		<h1>IF THERE IS ANY MESSAGE FOR YOU, HERE IT IS: %s</h1>
    <h1>REGISTER</h1>
		<form action="/register" method="POST">
			<label for="first">First</label>
			<input type="text" name="form_first" placeholder="First" id="first">
			<label for="first">Email</label>
			<input type="email" name="form_email" placeholder="Email">
			<label for="first">Password</label>
			<input type="password" name="form_password" placeholder="Password">
			<input type="submit">
		</form>
    <h1>LOG IN</h1>
    	<form action="/oauth/amazon/login" method="POST">
			<input type="submit" value="LOGIN WITH AMAZON">
		</form>
		<h1>LOGOUT</h1>
		<form action="/logout" method="POST">
			<input type="submit" value="LOGOUT">
		</form>
	</body>
	</html>`, f, e, errMsg)
}

// register registers first name, encryopted password, and email into db
func register(w http.ResponseWriter, r *http.Request) {
	// fmt.Println("registered r.method: ", r.Method)
	if r.Method != http.MethodPost {

		// https://golang.org/pkg/net/url/#QueryEscape
		// func QueryEscape(s string) string
		// QueryEscape escapes the string so it can be safely placed inside a URL query.
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	e := r.FormValue("form_email")
	if e == "" {
		msg := url.QueryEscape("your email needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	p := r.FormValue("form_password")
	if p == "" {
		msg := url.QueryEscape("your password needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	f := r.FormValue("form_first")
	if f == "" {
		msg := url.QueryEscape("your first name needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// byte password
	// func GenerateFromPassword(password []byte, cost int) ([]byte, error)
	// GenerateFromPassword returns the bcrypt hash of the password at the given cost.
	bsp, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		msg := "there was an internal server error"
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	log.Println("registered password: ", e)
	log.Println("registered bcrypted: ", bsp)
	// store credentials in the user map
	db[e] = user{
		password: bsp,
		First:    f,
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {

		// https://golang.org/pkg/net/url/#QueryEscape
		// func QueryEscape(s string) string
		// QueryEscape escapes the string so it can be safely placed inside a URL query.
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	e := r.FormValue("form_email")
	if e == "" {
		msg := url.QueryEscape("your email needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	p := r.FormValue("form_password")
	if p == "" {
		msg := url.QueryEscape("your password needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// check the database if the password exists
	if _, ok := db[e]; !ok {
		// login is definitely one place where you want your error message to be confusing for the user
		msg := url.QueryEscape("your email or password didn't match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// compare password
	err := bcrypt.CompareHashAndPassword(db[e].password, []byte(p))
	if err != nil {
		msg := url.QueryEscape("your email or password didn't match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	err = createSession(e, w)
	if err != nil {
		log.Println("couldn't createToken in login", err)
		msg := url.QueryEscape("Error, only let devs see the error info")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther) // to see info why the token can't be created
		return
	}

	msg := url.QueryEscape("you logged in " + e)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)

}

// if we're not creating a session, that means we're just signing a user id
/*
create a new session's uuid, create a signed token based on that uuid, creat and set a cookie with that token
*/
func createSession(email string, w http.ResponseWriter) error {
	// create a signed token from the UUID
	sUUID := uuid.New().String() // create uuid in a standard format
	sessions[sUUID] = email      // email
	// signed token
	token, err := createToken(sUUID) // create the token which comprises of (1) the signed HMAC based on the UUID and (2) the original session's UUID
	if err != nil {
		return fmt.Errorf("couldn't createtoken in createsession %w", err)
	}

	// create a cookie with the session's UUID and th esigned token
	cookie := http.Cookie{
		Name:  "sessionID",
		Value: token,
		Path:  "/", // A path that must exist in the requested URL, or the browser won't send the Cookie header.
		/*
			In Inspect --> Network --> http://localhost:8080/oauth/amazon/receive?code=ANMoWLxnXWLofiJBFNRk&scope=profile&state=f591ab8e-162e-4986-849c-2ae1c0190d84
			--> Header --> Response Header -- > Set-Cookie
			Without Path
				Set-Cookie: sessionID=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MTEyMjIyODgsIlNJRCI6IjBhMzlmZTY3LWQ3NGUtNDAzZC1hNDE5LTllNjJmNWZkZWY5YSJ9.YMu0AjB1XUi6_qUgj27a51QeHL-6V2sa3NnYdOKTdA4
			With Path
				Set-Cookie: sessionID=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MTEyMjQ2ODIsIlNJRCI6IjE0ZGU1NWQyLWNhYzctNDMzYi1hYWQ1LTVkNGEyMTk0NDRmNCJ9.zuyHu81YnWjdOtf7ghKpBV1ib92Za8RyCIAkVu9YU9k; Path=/
		*/
	}

	// put the cookie to the response writer
	http.SetCookie(w, &cookie) // set a Cookie to the response writer
	return nil
}

func logout(w http.ResponseWriter, r *http.Request) {
	// check if the methoid is correct
	// ***in term of vulnerability protection, always use POST for logout since someone can use GET with the image tag to let the image not load properly?
	// ??? vulnerability: can use a GET request to makea cookie from a site that can effect the other sites (endpoints)
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
		// redirect and return to prevent it from execute all the below codes
	}

	// check if there already is a cookie
	// func (r *Request) Cookie(name string) (*Cookie, error)
	c, err := r.Cookie("sessionID") // returns *Cookie
	if err != nil {
		c = &http.Cookie{ // c has to be the same type as *Cookie, so add "&""
			Name:  "sessionID",
			Value: "",
		}
	}

	sID, err := parseToken(c.Value) // returns xs to s
	if err != nil {
		log.Println("index pareseToken %w", err)
	}

	delete(sessions, sID)

	c.MaxAge = -1 // if <0 delete the cookie immediately

	http.SetCookie(w, c) // put the empty cookie to the responseWriter
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// create uuid, oauthEXP, then redirect to amazon reading our Config
func oAmazonlogin(w http.ResponseWriter, r *http.Request) {
	// this happens in our own site --------------------------
	if r.Method != http.MethodPost { // variable http.MethodPost = "POST"
		http.Redirect(w, r, "/", http.StatusSeeOther) // variable StatusSeeOther = "303"
		return
	}

	// "func New() UUID" doesn't mind the data type
	id := uuid.New().String()
	// we determine to allow how long before they redirect back to your site from the oauth2 provider, not how long the token lasts
	oauthExp[id] = time.Now().Add(time.Hour) // expire in an hour

	// // this will happen in the oauth2 provider's site --------------------------
	/*
		func (c *Config) AuthCodeURL(state string, opts ...AuthCodeOption) string // you can leave the optional variadic parameter out
		AuthCodeURL returns a URL to OAuth 2.0 provider's consent page that asks for permissions for the required scopes explicitly.
	*/
	// it adds state (secret), scope (permission0), and clientid in Config
	// redirect to amazon at the AuthURL endpoint (Endpoint.AuthURL = "https://www.amazon.com/ap/oa") with the added state (id) for security concern
	http.Redirect(w, r, oauth.AuthCodeURL(id), http.StatusSeeOther)
	// then amazon looks at all stuffs from our Config
}

// after login and give permission in amazon, we tell amazon to redirect to our receive page
/*
read state and code from amazon's sent url, check oauthEXP, exchange token from amazon's code,
create authenticated http client, GET request for the response body, decode JSON to Go based on profileResponse,
use uid to check email - if none, use that uid to ctreate a signed token, create a signed token
*/
func oAmazonReceive(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state") // from the GET url sent by amazon for exchangeing the token
	if state == "" {
		msg := url.QueryEscape("state was empty in oAmazonReceive")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// we got this code from amazon
	code := r.FormValue("code")
	if code == "" {
		msg := url.QueryEscape("code was empty in oAmazonReceive")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// Is the oauth expired, not the token
	expT := oauthExp[state]
	if time.Now().After(expT) {
		msg := url.QueryEscape("oauth took too long time.now.after")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// If the oauth is not expired, exchange our code for a token. This uses the client secret also. The tokenURL is called. We get back a token.
	/*
		func (c *Config) Exchange(ctx context.Context, code string, opts ...AuthCodeOption) (*Token, error)
		Exchange converts an authorization code into a token.
	*/
	token, err := oauth.Exchange(r.Context(), code) // talk to amazon server for a token
	if err != nil {
		msg := url.QueryEscape("couldn't do oauth exchange: " + err.Error()) // Error() returns string
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// interface TokenSource receives the token "t" (with both ther used and refreshed tokens)
	// it lets us get the current used token, or get the refreshed token automatically if the used one is expired
	// so we don't have to deal with the expired token by ourselves
	// Once we get the TokenSource, we ask for either AccessToken of RefreshToken (it also uses the Config because to use the RefereshToken, it might need the TokenURL and the ClientSecret)
	/*
		func (c *Config) TokenSource(ctx context.Context, t *Token) TokenSource
		TokenSource returns a TokenSource that returns t until t expires, automatically refreshing it as necessary using the provided context.
	*/
	// TokenSource() is creating something that implements TokenSource based off of that token and some from the Config
	tokenSource := oauth.TokenSource(r.Context(), token) // This token might have AccessToken or RefreshToekn. Don't need to care as long as it will give us one that works
	// create a http client that uses that token source to authenticate all calls through it.
	// our client gets a user profile, response body, and read the slice of byte
	client := oauth2.NewClient(r.Context(), tokenSource)

	/*
		func (c *Client) Get(url string) (resp *Response, err error)
		Get issues a GET to the specified URL.
	*/
	// use this endpoint (url) according to the GET provided from amazon (see amazon-notes.txt)
	resp, err := client.Get("https://api.amazon.com/user/profile") // Get request to get the response body
	// network error, can't issue GET
	if err != nil {
		msg := url.QueryEscape("couldn't get at amazon: " + err.Error())
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	defer resp.Body.Close() // response body needs to be closed (close the network connection) after using GET even if you aren't reading the body

	/*
		// most of the time bodies are in JSON format, so we can use JSON decoder. However, we don't know what JSON format is this one or how many bytes, and we try to print it out
		// Body is of type io.ReadCloser which has the embedded interface Reader inside it
		// if you use unmarshal, you will have to check and read the response body. If you use deocde, then you can jsut skip it.
		bs, err := ioutil.ReadAll(resp.Body) // resp is just struct, so we need to get into its body
		if err != nil {
			msg := url.QueryEscape("couldn't read resp body: " + err.Error())
			http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		}
	*/

	// Check status error
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// if it's not response 200, the body will show why it's not a valid call in there. So, let's show rthe body
		msg := url.QueryEscape("not a 200 resp code")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// create our Go struct for receiving JSON
	// use {"user_id":"amzn1.account.AEYVYJU4N35CYBQDCUPJBUYWF4JQ","name":"valor","email":"valor.vignette@gmail.com"}
	// and "https://mholt.github.io/json-to-go/". Change the struct name.
	type profileResponse struct { // structs aren't reference type, so the default values of the fields will be empty string
		UserID string `json:"user_id"`
		Name   string `json:"name"`
		Email  string `json:"email"`
	}

	var pr profileResponse

	/*
		func NewDecoder(r io.Reader) *Decoder
		NewDecoder returns a new decoder that reads from r.

		func (dec *Decoder) Decode(v interface{}) error
		Decode reads the next JSON-encoded value from its input and stores it in the value pointed to by v.
	*/
	err = json.NewDecoder(resp.Body).Decode(&pr) // decode the json into pr
	if err != nil {
		msg := url.QueryEscape("not able to decode json response ")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// For the current state, we don't have the registration and don't know about the code yet.
	// check to see if they have already registered at our site with this oauth2
	// it's the same code for login and register
	// if the user has already registered with this user ID from this oauth, we'll get back the email
	// key is uid from oauth provider; value is user id, eg, email
	eml, ok := oauthConnections[pr.UserID] // check the email from that uid in case there was a change of email in amzon before sending to us
	if !ok {
		// not registered at our site yet with amazon
		// register at our site with amazon
		// eml = "test@example.com" // refer to our test user in db

		// user id is a string used to create a signed token "st" based on user id
		st, err := createToken(pr.UserID)
		if err != nil {
			log.Println("couldn't createToken in oAmazonReceive", err)
			msg := url.QueryEscape("Error, only let devs see the error info")
			http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther) // to see info why the token can't be created
			return
		}

		// sst := url.QueryEscape(st) .. not used
		/*
			type Values map[string][]string
			Values maps a string key to a list of values. It is typically used for query parameters and form values. Unlike in the http.Header map, the keys in a Values map are case-sensitive.
		*/
		uv := url.Values{} // url value
		// we're going to a partial registry page, so we can pre populate that form with information
		/*
			func (v Values) Add(key, value string)
			Add adds the value to key. It appends to any existing values associated with key.
		*/
		uv.Add("sst", st) // sst is the signed token
		uv.Add("name", pr.Name)
		uv.Add("email", pr.Email)
		http.Redirect(w, r, "/partial-register?"+uv.Encode(), http.StatusSeeOther) // Encode encodes the values into “URL encoded” form ("bar=baz&foo=quux") sorted by key.
		return
	}

	// if the email is already registered the oauth with us, create a session with a cookie
	err = createSession(eml, w) // set a cookie with that email
	if err != nil {
		log.Println("couldn't createSession in oAmazonReceive", err)
		msg := url.QueryEscape("Error, only let devs see the error info")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther) // to see info why the token can't be created
		return
	}

	// display in the page that the user logins successfully
	msg := url.QueryEscape("you logged in " + eml)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)

}

// partially register and confirm that unrecognized email before sending to oAmazonRegister next
func partialRegister(w http.ResponseWriter, r *http.Request) {
	sst := r.FormValue("sst") // receive from "uv"
	name := r.FormValue("name")
	email := r.FormValue("email")

	if sst == "" {
		log.Println("couldn't get sst in partialRegister")
		msg := url.QueryEscape("Error, only let devs see the error info")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther) // to see info why the token can't be created
		return
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta http-equiv="X-UA-Compatible" content="ie=edge">
		<title>Document</title>
	</head>
	<body>
		<form action="/oauth/amazon/register" method="POST">
		
		<label for="firstName">FIRST NAME</label>
		<input type="text" name="first" id="firstName" value="%s">
		
		<label for="Email">EMAIL</label>
		<input type="text" name="email" id="Email" value="%s">
		
		<input type="hidden" value="%s" name="oauthID">
		
		<input type="submit">
		</form>
	</body>
	</html>`, name, email, sst)
}

func oAmazonRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	f := r.FormValue("first")
	e := r.FormValue("email")
	oauthID := r.FormValue("oauthID") // receive the token from the user's input in variable name="oauthID"

	if f == "" {
		msg := url.QueryEscape("your first name needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if e == "" {
		msg := url.QueryEscape("your email needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if oauthID == "" {
		// bots' banned IPs should be tenmporary since that would affect the real users
		log.Println("oauthID came through as empty at oAmazonRegister - MAYBE BAN THIS BOT PRANKSTER'S IP ADDRESS")
		msg := url.QueryEscape("your oauthID needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	amazonUID, err := parseToken(oauthID)
	if err != nil {
		log.Println("parseToken at oAmazonRegister didn't parse")
		msg := url.QueryEscape("there was an issue")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	db[e] = user{ // save the email in DB
		First: f,
	}

	// key is uuid from oauth provider; value is user id, e.g., email
	oauthConnections[amazonUID] = e

	err = createSession(e, w)
	if err != nil {
		log.Println("couldn't createSession in oAmazonRegister", err)
		msg := url.QueryEscape("Error, only let devs see the error info")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther) // to see info why the token can't be created
		return
	}
	// // We want to make sure our log endpoint doesn't accidentally log people in - using password
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
