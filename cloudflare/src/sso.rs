use crate::{auth::User, *};
use std::collections::HashMap;

pub fn config(env: &Env) -> ApiResult<String> {
    Ok(json!({"domain":env.var("AUTH0_DOMAIN")?.to_string(),"clientId":env.var("AUTH0_CLIENT_ID")?.to_string(),"audience":env.var("AUTH0_AUDIENCE")?.to_string(),"organization":env.var("AUTH0_ORGANIZATION_ID")?.to_string(),"permission":env.var("AUTH0_PERMISSION")?.to_string(),"callback":format!("{}/identity/connect/oidc-signin",domain(env)?)}).to_string())
}
async fn encrypt(env: &Env, value: &str, context: &str) -> ApiResult<String> {
    js_string(seal(value, &env.secret("TOKEN_ENCRYPTION_KEY")?.to_string(), context).await)
}
async fn decrypt(env: &Env, value: &str, context: &str) -> ApiResult<String> {
    js_string(unseal(value, &env.secret("TOKEN_ENCRYPTION_KEY")?.to_string(), context).await)
}
pub async fn session_identity(env: &Env, record: &Value) -> ApiResult<Value> {
    let context = record.get("session_id").unwrap_or(&record["id"]).as_str().ok_or(ApiError(401, "Invalid session"))?;
    let tokens: Value = serde_json::from_str(&decrypt(env, required(record, "token_box")?, context).await?)?;
    let verified = verify_auth0(required(&tokens, "access_token")?, &config(env)?)
        .await
        .map_err(|_| ApiError(401, "Auth0 authorization expired or denied"))?;
    Ok(serde_json::from_str(&verified.as_string().ok_or(ApiError(401, "Invalid Auth0 token"))?)?)
}
fn redirect(url: &str) -> ApiResult<Response> {
    url::Url::parse(url).map_err(|_| ApiError(400, "Invalid redirect"))?;
    let mut response = Response::empty()?.with_status(302);
    response.headers_mut().set("Location", url)?;
    Ok(response)
}
fn query(req: &Request) -> ApiResult<HashMap<String, String>> {
    Ok(req.url()?.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect())
}
pub async fn prevalidate(env: &Env) -> ApiResult<Response> {
    let at = time_ms() / 1000;
    response(
        json!({"token":auth::sign(env,json!({"iss":format!("{}|sso",domain(env)?),"purpose":"sso","nbf":at,"exp":at+120,"sub":"vaultwarden"})).await?}),
    )
}
pub async fn authorize(req: &Request, env: &Env) -> ApiResult<Response> {
    auth::throttle(req, env, "sso", 20).await?;
    let p = query(req)?;
    let get = |key: &str| p.get(key).map(String::as_str).unwrap_or("");
    if get("code_challenge_method") != "S256"
        || get("response_type") != "code"
        || get("code_challenge").len() != 43
        || get("state").is_empty()
        || get("state").len() > 1024
    {
        return Err(ApiError(400, "SSO requires authorization code and S256 PKCE"));
    }
    let d = domain(env)?;
    let target = match get("client_id") {
        "web" | "browser" => format!("{d}/sso-connector.html"),
        "mobile" => "bitwarden://sso-callback".into(),
        "desktop" if get("redirect_uri") == "bitwarden://sso-callback" => "bitwarden://sso-callback".into(),
        "desktop" | "cli" => {
            let raw = get("redirect_uri");
            if !(8065..=8070).any(|port| raw == format!("http://localhost:{port}")) {
                return Err(ApiError(400, "Unsupported loopback redirect"));
            }
            raw.to_string()
        }
        _ => return Err(ApiError(400, "Unsupported Bitwarden client")),
    };
    // Match the upstream canonical redirect; never accept a caller-controlled URL.
    if get("redirect_uri") != target {
        return Err(ApiError(400, "Invalid SSO redirect URI"));
    }
    if !get("ssoToken").is_empty() {
        auth::verify(env, get("ssoToken"), "sso").await?;
    }
    let id = random_secret();
    let nonce = random_secret();
    let binding = random_secret();
    let binding_hash = js_string(digest(&binding).await)?;
    db::batch(env,vec![("INSERT INTO sso_pending(id,client_state,challenge,client_id,redirect,nonce,binding,expires) VALUES(?,?,?,?,?,?,?,?)".into(),vec![json!(id),json!(get("state")),json!(get("code_challenge")),json!(get("client_id")),json!(target),json!(nonce),json!(binding_hash),json!(time_ms()/1000+600)])]).await?;
    let mut url = url::Url::parse(&format!("https://{}/authorize", env.var("AUTH0_DOMAIN")?))
        .map_err(|_| ApiError(503, "Auth0 configuration incomplete"))?;
    url.query_pairs_mut()
        .append_pair("client_id", &env.var("AUTH0_CLIENT_ID")?.to_string())
        .append_pair("redirect_uri", &format!("{d}/identity/connect/oidc-signin"))
        .append_pair("response_type", "code")
        .append_pair("scope", "openid profile email offline_access")
        .append_pair("audience", &env.var("AUTH0_AUDIENCE")?.to_string())
        .append_pair("organization", &env.var("AUTH0_ORGANIZATION_ID")?.to_string())
        .append_pair("state", &id)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", get("code_challenge"))
        .append_pair("code_challenge_method", "S256");
    let mut r = redirect(url.as_str())?;
    let secure = if req.url()?.scheme() == "https" {
        "; Secure"
    } else {
        ""
    };
    r.headers_mut().set(
        "Set-Cookie",
        &format!("vw_sso_binding={binding}; HttpOnly; SameSite=Lax; Path=/identity/connect/; Max-Age=600{secure}"),
    )?;
    Ok(r)
}
pub async fn callback(req: &Request, env: &Env) -> ApiResult<Response> {
    let p = query(req)?;
    let id = p.get("state").ok_or(ApiError(400, "Missing SSO state"))?;
    let row = db::one(
        env,
        "SELECT * FROM sso_pending WHERE id=? AND expires>? AND code_hash IS NULL",
        &[json!(id), json!(time_ms() / 1000)],
    )
    .await?
    .ok_or(ApiError(400, "SSO transaction expired or consumed"))?;
    let cookie = req.headers().get("Cookie")?.unwrap_or_default();
    let binding = cookie
        .split(';')
        .find_map(|p| p.trim().strip_prefix("vw_sso_binding="))
        .ok_or(ApiError(403, "SSO browser binding missing"))?;
    let hash = js_string(digest(binding).await)?;
    if !secure_equal(&hash, text(&row, "binding")).await? {
        return Err(ApiError(403, "SSO browser binding mismatch"));
    }
    let code = p.get("code").filter(|v| !v.is_empty()).ok_or(ApiError(403, "Auth0 login was not completed"))?;
    let client_code = random_secret();
    let code_hash = js_string(digest(&client_code).await)?;
    let encrypted = encrypt(env, code, id).await?;
    db::batch_result(
        env,
        vec![
            db::assertion(
                "SELECT COUNT(*) FROM sso_pending WHERE id=? AND expires>? AND code_hash IS NULL",
                vec![json!(id), json!(time_ms() / 1000)],
            ),
            (
                "UPDATE sso_pending SET code_hash=?,code_box=? WHERE id=?".into(),
                vec![json!(code_hash), json!(encrypted), json!(id)],
            ),
            ("DELETE FROM transaction_guard".into(), vec![]),
        ],
    )
    .await?;
    let mut target =
        url::Url::parse(required(&row, "redirect")?).map_err(|_| ApiError(400, "Invalid stored redirect"))?;
    target
        .query_pairs_mut()
        .append_pair("code", &client_code)
        .append_pair("state", required(&row, "client_state")?)
        .append_pair("scope", "api offline_access")
        .append_pair("iss", &domain(env)?);
    let mut r = redirect(target.as_str())?;
    r.headers_mut()
        .set("Set-Cookie", "vw_sso_binding=; HttpOnly; SameSite=Lax; Path=/identity/connect/; Max-Age=0; Secure")?;
    Ok(r)
}
pub async fn login(req: &mut Request, env: &Env) -> ApiResult<Response> {
    auth::throttle(req, env, "login", 20).await?;
    let p: HashMap<String, String> = url::form_urlencoded::parse(req.text().await?.as_bytes())
        .map(|(k, v)| (k.to_lowercase().replace('_', ""), v.into_owned()))
        .collect();
    let get = |key: &str| p.get(key).map(String::as_str).unwrap_or("");
    if get("granttype") == "refresh_token" {
        return refresh(env, get("refreshtoken"), get("clientid")).await;
    }
    if get("granttype") != "authorization_code" {
        return Err(ApiError(400, "Use Auth0 SSO; local password and API-key login are disabled"));
    }
    let hash = js_string(digest(get("code")).await)?;
    let pending = db::one(
        env,
        "SELECT * FROM sso_pending WHERE code_hash=? AND expires>?",
        &[json!(hash), json!(time_ms() / 1000)],
    )
    .await?
    .ok_or(ApiError(400, "Invalid or consumed SSO code"))?;
    if get("codeverifier").len() < 43
        || get("codeverifier").len() > 128
        || !secure_equal(&js_string(digest(get("codeverifier")).await)?, text(&pending, "challenge")).await?
        || get("clientid") != text(&pending, "client_id")
    {
        return Err(ApiError(400, "Invalid SSO client or PKCE verifier"));
    }
    let device = get("deviceidentifier");
    let name = get("devicename");
    let device_type = get("devicetype").parse::<i64>().map_err(|_| ApiError(400, "Invalid device type"))?;
    if device.is_empty()
        || device.len() > 128
        || name.is_empty()
        || name.len() > 256
        || !(0..=50).contains(&device_type)
    {
        return Err(ApiError(400, "Invalid device"));
    }
    // Consume the local code before calling Auth0. A failed exchange requires restarting SSO.
    db::batch_result(
        env,
        vec![
            db::assertion(
                "SELECT COUNT(*) FROM sso_pending WHERE id=? AND code_hash=? AND expires>?",
                vec![pending["id"].clone(), json!(hash), json!(time_ms() / 1000)],
            ),
            ("DELETE FROM sso_pending WHERE id=?".into(), vec![pending["id"].clone()]),
            ("DELETE FROM transaction_guard".into(), vec![]),
        ],
    )
    .await?;
    let code = decrypt(env, required(&pending, "code_box")?, required(&pending, "id")?).await?;
    let exchanged = exchange_auth0(&code, get("codeverifier"), required(&pending, "nonce")?, &config(env)?)
        .await
        .map_err(|_| ApiError(403, "Auth0 login or password-vault permission was denied"))?;
    let result: Value = serde_json::from_str(&exchanged.as_string().ok_or(ApiError(403, "Invalid Auth0 response"))?)?;
    let identity = &result["claims"];
    let subject = required(identity, "sub")?;
    let email = required(identity, "email")?;
    // Auth0 subject is the only identity key. No matching or account linking by email.
    db::batch(env,vec![("INSERT INTO users(id,auth0_sub,email,kdf_salt,name,kdf,iterations,stamp,created,revision) VALUES(?,?,?,?,?,0,600000,?,?,?) ON CONFLICT(auth0_sub) DO NOTHING".into(),vec![json!(random_id()),json!(subject),json!(email),json!(email),identity["name"].clone(),json!(random_id()),json!(date()),json!(time_ms())])]).await?;
    let data = db::one(env, "SELECT * FROM users WHERE auth0_sub=?", &[json!(subject)])
        .await?
        .ok_or(ApiError(500, "Vault metadata could not be loaded"))?;
    let user = User {
        data,
        session: random_id(),
    };
    let refresh = random_secret();
    let refresh_hash = js_string(digest(&refresh).await)?;
    let token_box = encrypt(env, &result["tokens"].to_string(), &user.session).await?;
    let expiry = identity["exp"].as_i64().ok_or(ApiError(403, "Invalid Auth0 expiry"))?;
    let session = json!({"id":user.session,"device_id":device,"device_type":device_type,"client_id":get("clientid"),"auth_exp":expiry});
    db::batch_result(env,vec![db::assertion("SELECT COUNT(*) FROM users WHERE id=? AND stamp=?",vec![user.id(),user.stamp()]),("DELETE FROM sessions WHERE user_id=? AND device_id=?".into(),vec![user.id(),json!(device)]),("INSERT INTO sessions(id,user_id,device_id,device_name,device_type,client_id,stamp,refresh_hash,expires,auth_exp,token_box,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)".into(),vec![json!(user.session),user.id(),json!(device),json!(name),json!(device_type),json!(get("clientid")),user.stamp(),json!(refresh_hash),json!(time_ms()/1000+30*86400),json!(expiry),json!(token_box),json!(time_ms()/1000)]),("DELETE FROM transaction_guard".into(),vec![])]).await?;
    tokens(env, &user, &session, &refresh).await
}
async fn refresh(env: &Env, raw: &str, client: &str) -> ApiResult<Response> {
    if raw.is_empty() {
        return Err(ApiError(400, "Missing refresh token"));
    }
    let hash = js_string(digest(raw).await)?;
    let lock = random_id();
    let session=db::one(env,"UPDATE sessions SET refreshing=? WHERE refresh_hash=? AND expires>? AND refreshing IS NULL AND (?='' OR client_id=?) AND stamp=(SELECT stamp FROM users WHERE id=sessions.user_id) RETURNING *",&[json!(lock),json!(hash),json!(time_ms()/1000),json!(client),json!(client)]).await?.ok_or(ApiError(400,"Refresh token invalid or already in use"))?;
    if !client.is_empty() && session["client_id"] != client {
        return Err(ApiError(400, "Wrong refresh client"));
    }
    let result = refresh_locked(env, &session, &lock).await;
    if result.is_err() {
        // Fail closed if the external rotation and D1 commit cannot both complete.
        db::batch(
            env,
            vec![("DELETE FROM sessions WHERE id=? AND refreshing=?".into(), vec![session["id"].clone(), json!(lock)])],
        )
        .await?;
    }
    result
}
async fn refresh_locked(env: &Env, session: &Value, lock: &str) -> ApiResult<Response> {
    let old: Value =
        serde_json::from_str(&decrypt(env, required(session, "token_box")?, required(session, "id")?).await?)?;
    let refreshed = refresh_auth0(required(&old, "refresh_token")?, &config(env)?)
        .await
        .map_err(|_| ApiError(400, "Auth0 session expired or permission revoked; log in again"))?;
    let result: Value =
        serde_json::from_str(&refreshed.as_string().ok_or(ApiError(400, "Invalid Auth0 refresh response"))?)?;
    let data = db::one(env, "SELECT * FROM users WHERE id=?", &[session["user_id"].clone()])
        .await?
        .ok_or(ApiError(400, "Vault not found"))?;
    if result["claims"]["sub"] != data["auth0_sub"] {
        return Err(ApiError(400, "Auth0 refresh identity mismatch"));
    }
    let user = User {
        data,
        session: required(session, "id")?.into(),
    };
    let refresh = random_secret();
    let hash = js_string(digest(&refresh).await)?;
    let encrypted = encrypt(env, &result["tokens"].to_string(), &user.session).await?;
    let expiry = result["claims"]["exp"].as_i64().ok_or(ApiError(400, "Invalid refresh expiry"))?;
    db::batch_result(env,vec![db::assertion("SELECT COUNT(*) FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.id=? AND s.refreshing=? AND s.stamp=u.stamp AND u.stamp=?",vec![json!(user.session),json!(lock),user.stamp()]),("UPDATE sessions SET refresh_hash=?,auth_exp=?,token_box=?,refreshing=NULL,expires=? WHERE id=?".into(),vec![json!(hash),json!(expiry),json!(encrypted),json!(time_ms()/1000+30*86400),json!(user.session)]),("DELETE FROM transaction_guard".into(),vec![])]).await?;
    let mut updated = session.clone();
    updated["auth_exp"] = json!(expiry);
    tokens(env, &user, &updated, &refresh).await
}
async fn tokens(env: &Env, u: &User, session: &Value, refresh: &str) -> ApiResult<Response> {
    let at = time_ms() / 1000;
    let expires = session["auth_exp"].as_i64().ok_or(ApiError(400, "Invalid Auth0 expiry"))?.min(at + 3600);
    let d = &u.data;
    if expires <= at {
        return Err(ApiError(400, "Auth0 session expired"));
    }
    let access=auth::sign(env,json!({"iss":format!("{}|login",domain(env)?),"purpose":"login","nbf":at,"exp":expires,"sub":u.id(),"premium":true,"name":d["name"],"email":d["email"],"email_verified":true,"sstamp":u.stamp(),"sid":u.session,"device":session["device_id"],"devicetype":session["device_type"].to_string(),"client_id":session["client_id"],"scope":["api","offline_access"],"amr":["Application","sso"]})).await?;
    let has_key = !text(d, "wrapped_key").is_empty();
    response(
        json!({"access_token":access,"expires_in":expires-at,"refresh_token":refresh,"token_type":"Bearer","scope":"api offline_access","Key":if has_key {d["wrapped_key"].clone()}else{Value::Null},"PrivateKey":d["private_key"],"Kdf":d["kdf"],"KdfIterations":d["iterations"],"KdfMemory":d["memory"],"KdfParallelism":d["parallelism"],"ForcePasswordReset":false,"MasterPasswordPolicy":{"Object":"masterPasswordPolicy","EnforceOnLogin":false},"AccountKeys":u.keys(),"UserDecryptionOptions":{"HasMasterPassword":has_key,"MasterPasswordUnlock":u.unlock(true),"Object":"userDecryptionOptions"}}),
    )
}
