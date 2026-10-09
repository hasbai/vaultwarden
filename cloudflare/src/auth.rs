use crate::*;

pub struct User {
    pub data: Value,
    pub session: String,
}
impl User {
    pub fn id(&self) -> Value {
        self.data["id"].clone()
    }
    pub fn stamp(&self) -> Value {
        self.data["stamp"].clone()
    }
    pub fn profile(&self) -> Value {
        json!({"id":self.id(),"name":self.data["name"],"email":self.data["email"],"emailVerified":self.data["email_verified"]==1,"premium":true,"premiumFromOrganization":false,"culture":"en-US","twoFactorEnabled":false,"key":self.data["wrapped_key"],"privateKey":self.data["private_key"],"securityStamp":self.stamp(),"organizations":[],"organizationsNew":[],"providers":[],"providerOrganizations":[],"forcePasswordReset":false,"avatarColor":self.data["avatar"],"usesKeyConnector":false,"creationDate":self.data["created"],"accountKeys":self.keys(),"object":"profile"})
    }
    pub fn keys(&self) -> Value {
        if self.data["private_key"].is_null() {
            return Value::Null;
        }
        json!({"publicKeyEncryptionKeyPair":{"wrappedPrivateKey":self.data["private_key"],"publicKey":self.data["public_key"],"signedPublicKey":null,"object":"publicKeyEncryptionKeyPair"},"securityState":null,"signatureKeyPair":null,"object":"privateKeys"})
    }
    pub fn unlock(&self, upper: bool) -> Value {
        let d = &self.data;
        if text(d, "wrapped_key").is_empty() {
            return Value::Null;
        }
        if upper {
            json!({"Kdf":{"KdfType":d["kdf"],"Iterations":d["iterations"],"Memory":d["memory"],"Parallelism":d["parallelism"]},"MasterKeyEncryptedUserKey":d["wrapped_key"],"MasterKeyWrappedUserKey":d["wrapped_key"],"Salt":d["kdf_salt"]})
        } else {
            json!({"kdf":{"kdfType":d["kdf"],"iterations":d["iterations"],"memory":d["memory"],"parallelism":d["parallelism"]},"masterKeyEncryptedUserKey":d["wrapped_key"],"masterKeyWrappedUserKey":d["wrapped_key"],"salt":d["kdf_salt"]})
        }
    }
}
pub(crate) async fn sign(env: &Env, claims: Value) -> ApiResult<String> {
    js_string(sign_jwt(&claims.to_string(), &env.secret("JWT_JWK")?.to_string()).await)
}
pub(crate) async fn verify(env: &Env, token: &str, purpose: &str) -> ApiResult<Value> {
    let s = verify_jwt(token, &env.secret("JWT_JWK")?.to_string(), &format!("{}|{purpose}", domain(env)?), purpose)
        .await
        .map_err(|_| ApiError(401, "Invalid or expired token"))?;
    Ok(serde_json::from_str(&s.as_string().ok_or(ApiError(401, "Invalid token"))?)?)
}
pub async fn authenticate(req: &Request, env: &Env) -> ApiResult<User> {
    let header = req.headers().get("Authorization")?.ok_or(ApiError(401, "Authentication required"))?;
    let token = header.strip_prefix("Bearer ").ok_or(ApiError(401, "Authentication required"))?;
    let claims = verify(env, token, "login").await?;
    let data=db::one(env,"SELECT u.*,s.token_box,s.id AS session_id FROM users u JOIN sessions s ON s.user_id=u.id WHERE u.id=? AND u.stamp=? AND s.id=? AND s.stamp=u.stamp AND s.expires>?",&[claims["sub"].clone(),claims["sstamp"].clone(),claims["sid"].clone(),json!(time_ms()/1000)]).await?.ok_or(ApiError(401,"Session has been revoked"))?;
    let identity = crate::sso::session_identity(env, &data).await?;
    if identity["sub"] != data["auth0_sub"] {
        return Err(ApiError(401, "Invalid Auth0 session"));
    }
    Ok(User {
        data,
        session: required(&claims, "sid")?.to_owned(),
    })
}
pub async fn throttle(req: &Request, env: &Env, kind: &str, limit: i64) -> ApiResult<()> {
    let ip = req.headers().get("CF-Connecting-IP")?.unwrap_or_else(|| "local".into());
    let key = js_string(digest(&format!("{kind}:{ip}")).await)?;
    let window = time_ms() / 60000;
    let row=db::one(env,"INSERT INTO throttle(key,window,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN window=excluded.window THEN count+1 ELSE 1 END,window=excluded.window RETURNING count",&[json!(key),json!(window)]).await?.ok_or(ApiError(500,"Rate limit failed"))?;
    if row["count"].as_i64().unwrap_or(limit + 1) > limit {
        return Err(ApiError(429, "Too many attempts; wait one minute"));
    }
    Ok(())
}
pub async fn check_password(user: &User, env: &Env, password: &str) -> ApiResult<()> {
    account_throttle(user, env).await?;
    if !text(&user.data, "verifier").starts_with("hmac-sha256:v1:") {
        return Err(ApiError(403, "Unsupported vault verifier"));
    }
    let actual = verifier(env, &user.data, password, text(&user.data, "salt")).await?;
    if !secure_equal(&actual, text(&user.data, "verifier")).await? {
        return Err(ApiError(400, "Invalid password"));
    }
    Ok(())
}
pub async fn verifier(env: &Env, user: &Value, client_hash: &str, salt: &str) -> ApiResult<String> {
    js_string(
        password_hash(client_hash, salt, required(user, "id")?, &env.secret("VAULT_VERIFIER_KEY")?.to_string()).await,
    )
    .map_err(|_| ApiError(400, "Invalid client authentication hash or verifier configuration"))
}
pub async fn account_throttle(user: &User, env: &Env) -> ApiResult<()> {
    let key = format!("vault-password:{}", required(&user.data, "id")?);
    let window = time_ms() / 60000;
    let row=db::one(env,"INSERT INTO throttle(key,window,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN window=excluded.window THEN count+1 ELSE 1 END,window=excluded.window RETURNING count",&[json!(key),json!(window)]).await?.ok_or(ApiError(500,"Rate limit failed"))?;
    if row["count"].as_i64().unwrap_or(11) > 10 {
        return Err(ApiError(429, "Too many password attempts; wait one minute"));
    }
    Ok(())
}
pub fn kdf(value: &Value) -> ApiResult<(Value, Value, Value, Value)> {
    let kind = value.get("kdfType").or_else(|| value.get("kdf")).and_then(Value::as_i64).unwrap_or(0);
    let iterations =
        value.get("iterations").or_else(|| value.get("kdfIterations")).and_then(Value::as_i64).unwrap_or(600000);
    let memory = value.get("memory").or_else(|| value.get("kdfMemory")).cloned().unwrap_or(Value::Null);
    let parallelism = value.get("parallelism").or_else(|| value.get("kdfParallelism")).cloned().unwrap_or(Value::Null);
    if kind == 0 && (100000..=10_000_000).contains(&iterations) {
        return Ok((json!(kind), json!(iterations), Value::Null, Value::Null));
    }
    if kind == 1
        && (1..=100).contains(&iterations)
        && memory.as_i64().is_some_and(|v| (15..=1024).contains(&v))
        && parallelism.as_i64().is_some_and(|v| (1..=16).contains(&v))
    {
        return Ok((json!(kind), json!(iterations), memory, parallelism));
    }
    Err(ApiError(400, "Invalid client KDF parameters"))
}
pub async fn prelogin(req: &mut Request, env: &Env) -> ApiResult<Response> {
    throttle(req, env, "prelogin", 60).await?;
    let data: Value = req.json().await?;
    let email = required(&data, "email")?.trim().to_lowercase();
    let user = db::one(env, "SELECT kdf,iterations,memory,parallelism FROM users WHERE kdf_salt=?", &[json!(email)])
        .await?
        .unwrap_or(json!({"kdf":0,"iterations":600000,"memory":null,"parallelism":null}));
    response(
        json!({"kdf":user["kdf"],"kdfIterations":user["iterations"],"kdfMemory":user["memory"],"kdfParallelism":user["parallelism"],"kdfSettings":{"kdfType":user["kdf"],"iterations":user["iterations"],"memory":user["memory"],"parallelism":user["parallelism"]},"salt":null}),
    )
}
