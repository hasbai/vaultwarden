mod auth;
mod db;
mod sso;
mod vault;

use serde_json::{Value, json};
use wasm_bindgen::prelude::*;
use worker::*;

#[wasm_bindgen(module = "/src/crypto.js")]
unsafe extern "C" {
    #[wasm_bindgen(js_name = randomId)]
    fn random_id() -> String;
    #[wasm_bindgen(js_name = randomSecret)]
    fn random_secret() -> String;
    fn now() -> f64;
    #[wasm_bindgen(js_name = isoDate)]
    fn iso_date(ms: f64) -> String;
    #[wasm_bindgen(js_name = nextDate)]
    fn next_date(previous: &str) -> String;
    #[wasm_bindgen(catch)]
    async fn digest(value: &str) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(catch)]
    async fn equal(a: &str, b: &str) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(catch, js_name = passwordHash)]
    async fn password_hash(password: &str, salt: &str) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(catch, js_name = signJwt)]
    async fn sign_jwt(claims: &str, jwk: &str) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(catch, js_name = verifyJwt)]
    async fn verify_jwt(token: &str, jwk: &str, issuer: &str, purpose: &str) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(catch)]
    async fn seal(value: &str, secret: &str, context: &str) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(catch)]
    async fn unseal(value: &str, secret: &str, context: &str) -> std::result::Result<JsValue, JsValue>;
}

#[wasm_bindgen(module = "/src/auth0.js")]
unsafe extern "C" {
    #[wasm_bindgen(catch, js_name = verifyAuth0)]
    async fn verify_auth0(token: &str, config: &str) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(catch, js_name = exchangeAuth0)]
    async fn exchange_auth0(
        code: &str,
        verifier: &str,
        nonce: &str,
        config: &str,
    ) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(catch, js_name = refreshAuth0)]
    async fn refresh_auth0(token: &str, config: &str) -> std::result::Result<JsValue, JsValue>;
}

pub(crate) struct ApiError(pub u16, pub &'static str);
pub(crate) type ApiResult<T> = std::result::Result<T, ApiError>;
impl From<worker::Error> for ApiError {
    fn from(_: worker::Error) -> Self {
        Self(500, "Database or runtime operation failed")
    }
}
impl From<serde_json::Error> for ApiError {
    fn from(_: serde_json::Error) -> Self {
        Self(400, "Invalid JSON")
    }
}
pub(crate) fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}
pub(crate) fn required<'a>(v: &'a Value, key: &str) -> ApiResult<&'a str> {
    let s = text(v, key);
    if s.is_empty() || s.len() > 1_000_000 {
        Err(ApiError(400, "Missing or oversized field"))
    } else {
        Ok(s)
    }
}
pub(crate) fn time_ms() -> i64 {
    now() as i64
}
pub(crate) fn date() -> String {
    iso_date(now())
}
pub(crate) fn domain(env: &Env) -> ApiResult<String> {
    Ok(env.var("DOMAIN")?.to_string().trim_end_matches('/').to_string())
}
pub(crate) fn js_string(v: std::result::Result<JsValue, JsValue>) -> ApiResult<String> {
    v.map_err(|_| ApiError(500, "Cryptographic operation failed"))?
        .as_string()
        .ok_or(ApiError(500, "Invalid crypto result"))
}
pub(crate) async fn secure_equal(a: &str, b: &str) -> ApiResult<bool> {
    Ok(equal(a, b).await.map_err(|_| ApiError(500, "Cryptographic operation failed"))?.as_bool().unwrap_or(false))
}
pub(crate) fn response(value: Value) -> ApiResult<Response> {
    Ok(Response::from_json(&value)?)
}
pub(crate) fn empty() -> ApiResult<Response> {
    Ok(Response::empty()?.with_status(204))
}
pub(crate) fn list(values: Vec<Value>) -> Value {
    json!({"data":values,"object":"list","continuationToken":null})
}

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let result = route(&mut req, &env).await;
    match result {
        Ok(r) => Ok(r),
        Err(ApiError(code, msg)) => {
            if code >= 500 {
                console_error!("{{\"event\":\"api_failed\",\"status\":{code}}}");
            }
            let mut value = json!({"message":msg,"validationErrors":{"": [msg]},"object":"error"});
            if req.path() == "/identity/connect/token" {
                value = json!({"error":"invalid_grant","error_description":msg,"ErrorModel":{"Message":msg,"Object":"error"}});
            }
            Ok(Response::from_json(&value)?.with_status(code))
        }
    }
}
async fn route(req: &mut Request, env: &Env) -> ApiResult<Response> {
    let path = req.path();
    let method = req.method();
    if method == Method::Options {
        return empty();
    }
    if path == "/setup" {
        return Err(ApiError(404, "Use Auth0 SSO"));
    }
    if path == "/api/alive" {
        env.d1("DB")?.prepare("SELECT 1").first::<Value>(None).await?;
        return response(json!(date()));
    }
    if path == "/api/now" {
        return response(json!(date()));
    }
    if path == "/api/version" {
        return response(json!("worker-personal-0.1.0"));
    }
    if path == "/api/config" {
        let d = domain(env)?;
        return response(
            json!({"version":"2026.6.0","server":{"name":"Vaultwarden Worker (personal)","url":"https://github.com/hasbai/vaultwarden"},"settings":{"disableUserRegistration":true,"suppressOnboardingInterstitials":true},"environment":{"vault":d,"api":format!("{d}/api"),"identity":format!("{d}/identity"),"notifications":format!("{d}/notifications"),"sso":format!("{d}/identity"),"cloudRegion":null},"push":{"pushTechnology":0,"vapidPublicKey":null},"featureStates":{"pm-19148-innovation-archive":true},"communication":null,"object":"config"}),
        );
    }
    if matches!(
        path.as_str(),
        "/identity/accounts/prelogin" | "/identity/accounts/prelogin/password" | "/api/accounts/prelogin"
    ) && method == Method::Post
    {
        return auth::prelogin(req, env).await;
    }
    if path == "/identity/connect/token" && method == Method::Post {
        return sso::login(req, env).await;
    }
    if path == "/identity/accounts/register/send-verification-email" && method == Method::Post {
        return Err(ApiError(403, "Identity registration is managed by Auth0"));
    }
    if matches!(
        path.as_str(),
        "/api/accounts/register" | "/identity/accounts/register" | "/identity/accounts/register/finish"
    ) && method == Method::Post
    {
        return Err(ApiError(403, "Identity registration is managed by Auth0"));
    }
    if path == "/identity/sso/prevalidate" && method == Method::Get {
        return sso::prevalidate(env).await;
    }
    if path == "/identity/connect/authorize" && method == Method::Get {
        return sso::authorize(req, env).await;
    }
    if path == "/identity/connect/oidc-signin" && method == Method::Get {
        return sso::callback(req, env).await;
    }
    if path.starts_with("/api/") {
        let user = auth::authenticate(req, env).await?;
        return vault::route(req, env, &user).await;
    }
    if path.starts_with("/identity/")
        || path.starts_with("/notifications/")
        || path.starts_with("/admin")
        || path.starts_with("/icons/")
        || path.starts_with("/attachments/")
    {
        return Err(ApiError(404, "Feature is unavailable in the personal Worker"));
    }
    Ok(env.service("ASSETS")?.fetch_request(req.clone()?).await?)
}

#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let cutoff = iso_date((time_ms() - 30 * 86400 * 1000) as f64);
    let result=db::batch(&env,vec![
        ("UPDATE users SET revision=MAX(revision+1,?) WHERE id IN (SELECT user_id FROM ciphers WHERE deleted IS NOT NULL AND deleted<?)".into(),vec![json!(time_ms()),json!(cutoff)]),
        ("DELETE FROM ciphers WHERE deleted IS NOT NULL AND deleted<?".into(),vec![json!(cutoff)]),
        ("DELETE FROM sessions WHERE expires<?".into(),vec![json!(time_ms()/1000)]),
        ("DELETE FROM sso_pending WHERE expires<?".into(),vec![json!(time_ms()/1000)]),
        ("DELETE FROM throttle WHERE window<?".into(),vec![json!(time_ms()/60000-60)])
    ]).await;
    if result.is_err() {
        console_error!("{{\"event\":\"cleanup_failed\"}}");
    }
}
