//!
//! This example showcases the process of integrating with the
//! [GitHub OpenID Connect](https://token.actions.githubusercontent.com/.well-known/openid-configuration)
//! provider.
//!
//! Before running it, you'll need to [register your own app](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app) and get the client ID and secret.
//!
//! In order to run the example call:
//!
//! ```sh
//! CLIENT_ID=xxx CLIENT_SECRET=yyy cargo run --example github
//! ```
//!
//! ...and follow the instructions.
//!

use oauth2::{AuthUrl, TokenUrl};
use openidconnect::core::{
    CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::{
    reqwest, EmptyAdditionalProviderMetadata, JsonWebKeySetUrl, ResponseType, ResponseTypes,
    UserInfoUrl,
};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, RedirectUrl, Scope,
};
use url::Url;

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::exit;

fn handle_error<T: std::error::Error>(fail: &T, msg: &'static str) {
    let mut err_msg = format!("ERROR: {}", msg);
    let mut cur_fail: Option<&dyn std::error::Error> = Some(fail);
    while let Some(cause) = cur_fail {
        err_msg += &format!("\n    caused by: {}", cause);
        cur_fail = cause.source();
    }
    println!("{}", err_msg);
    exit(1);
}

fn main() {
    env_logger::init();

    let client_id =
        ClientId::new(env::var("CLIENT_ID").expect("Missing the CLIENT_ID environment variable."));
    let client_secret = ClientSecret::new(
        env::var("CLIENT_SECRET").expect("Missing the CLIENT_SECRET environment variable."),
    );
    let issuer_url = IssuerUrl::new("https://token.actions.githubusercontent.com".to_string())
        .unwrap_or_else(|err| {
            handle_error(&err, "Invalid issuer URL");
            unreachable!();
        });

    let http_client = reqwest::blocking::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to build HTTP client");
            unreachable!();
        });

    // Fetch GitHub's OpenID Connect discovery document.
    // let provider_metadata = CoreProviderMetadata::discover(&issuer_url, &http_client)
    //     .unwrap_or_else(|err| {
    //         handle_error(&err, "Failed to discover OpenID Provider");
    //         unreachable!();
    //     })
    //     .set_authorization_endpoint(
    //         AuthUrl::new("https://token.actions.githubusercontent.com".to_string()).unwrap(),
    //     );

    let provider_metadata = CoreProviderMetadata::new(
        IssuerUrl::new("https://token.actions.githubusercontent.com".to_string()).unwrap(),
        AuthUrl::new("https://github.com/login/oauth/authorize".to_string()).unwrap(),
        JsonWebKeySetUrl::new(
            "https://token.actions.githubusercontent.com/.well-known/jwks".to_string(),
        )
        .unwrap(),
        vec![ResponseTypes::new(vec![CoreResponseType::IdToken])],
        vec![
            CoreSubjectIdentifierType::Public,
            CoreSubjectIdentifierType::Pairwise,
        ],
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(
        TokenUrl::new("https://github.com/login/oauth/access_token".to_string()).unwrap(),
    ))
    .set_scopes_supported(Some(vec![Scope::new("openid".to_string())]))
    .set_userinfo_endpoint(Some(
        UserInfoUrl::new("https://api.github.com/user".to_string()).unwrap(),
    ));

    // Set up the config for the GitHub OAuth2 process.
    let client =
        CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
            // This example will be running its own server at localhost:8080.
            // See below for the server implementation.
            .set_redirect_uri(
                RedirectUrl::new("http://localhost:8080".to_string()).unwrap_or_else(|err| {
                    handle_error(&err, "Invalid redirect URL");
                    unreachable!();
                }),
            );

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // This example is requesting access to the email address and user profile.
        // .add_scope(Scope::new("emails".to_string()))
        // .add_scope(Scope::new("profile".to_string()))
        .url();

    println!("Open this URL in your browser:\n{}\n", authorize_url);

    let (code, state) = {
        // A very naive implementation of the redirect server.
        let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

        // Accept one connection
        let (mut stream, _) = listener.accept().unwrap();

        let mut reader = BufReader::new(&stream);

        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();

        let redirect_url = request_line.split_whitespace().nth(1).unwrap();
        let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

        let code = url
            .query_pairs()
            .find(|(key, _)| key == "code")
            .map(|(_, code)| AuthorizationCode::new(code.into_owned()))
            .unwrap();

        let state = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, state)| CsrfToken::new(state.into_owned()))
            .unwrap();

        let message = "Go back to your terminal :)";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
            message.len(),
            message
        );
        stream.write_all(response.as_bytes()).unwrap();

        (code, state)
    };

    println!("GitHub returned the following code:\n{}\n", code.secret());
    println!(
        "GitHub returned the following state:\n{} (expected `{}`)\n",
        state.secret(),
        csrf_state.secret()
    );

    // Exchange the code with a token.
    let token_response = client
        .exchange_code(code)
        .unwrap_or_else(|err| {
            handle_error(&err, "No user info endpoint");
            unreachable!();
        })
        .request(&http_client)
        .unwrap_or_else(|err| {
            handle_error(&err, "Failed to contact token endpoint");
            unreachable!();
        });

    println!(
        "GitHub returned access token:\n{}\n",
        token_response.access_token().secret()
    );
    println!("GitHub returned scopes: {:?}", token_response.scopes());

    let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
    // let id_token_claims: &CoreIdTokenClaims = token_response
    //     .extra_fields()
    //     .id_token()
    //     .expect("Server did not return an ID token")
    //     .claims(&id_token_verifier, &nonce)
    //     .unwrap_or_else(|err| {
    //         handle_error(&err, "Failed to verify ID token");
    //         unreachable!();
    //     });
    // println!("GitHub returned ID token: {:?}", id_token_claims);

    dbg!(token_response);

    // let id_token_claims = token_response.extra_fields();
    // dbg!(id_token_claims);
}
