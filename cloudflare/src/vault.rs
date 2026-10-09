use crate::{auth::User, *};
use std::collections::HashSet;

async fn body(req: &mut Request) -> ApiResult<Value> {
    Ok(req.json().await?)
}
fn nullable(v: &Value, key: &str) -> Value {
    v.get(key).cloned().unwrap_or(Value::Null)
}
fn folder(row: Value) -> Value {
    json!({"id":row["id"],"name":row["name"],"revisionDate":row["revision"],"object":"folder"})
}
fn cipher(row: Value) -> ApiResult<Value> {
    let mut p: Value = serde_json::from_str(required(&row, "payload")?)?;
    p["id"] = row["id"].clone();
    p["folderId"] = row["folder_id"].clone();
    p["creationDate"] = row["created"].clone();
    p["revisionDate"] = row["revision"].clone();
    p["deletedDate"] = row["deleted"].clone();
    p["archivedDate"] = row["archived"].clone();
    p["organizationId"] = Value::Null;
    p["attachments"] = Value::Null;
    p["organizationUseTotp"] = json!(true);
    p["collectionIds"] = json!([]);
    p["edit"] = json!(true);
    p["viewPassword"] = json!(true);
    p["permissions"] = json!({"delete":true,"restore":true});
    p["object"] = json!("cipherDetails");
    Ok(p)
}
async fn folders(env: &Env, u: &User) -> ApiResult<Vec<Value>> {
    Ok(db::all(env, "SELECT * FROM folders WHERE user_id=?", &[u.id()]).await?.into_iter().map(folder).collect())
}
async fn ciphers(env: &Env, u: &User) -> ApiResult<Vec<Value>> {
    db::all(env, "SELECT * FROM ciphers WHERE user_id=?", &[u.id()]).await?.into_iter().map(cipher).collect()
}
async fn get_cipher(env: &Env, u: &User, id: &str) -> ApiResult<Value> {
    db::one(env, "SELECT * FROM ciphers WHERE id=? AND user_id=?", &[json!(id), u.id()])
        .await?
        .ok_or(ApiError(404, "Item not found"))
}
async fn get_folder(env: &Env, u: &User, id: &str) -> ApiResult<Value> {
    db::one(env, "SELECT * FROM folders WHERE id=? AND user_id=?", &[json!(id), u.id()])
        .await?
        .ok_or(ApiError(404, "Folder not found"))
}
fn encrypted_name(v: &Value) -> ApiResult<()> {
    let name = required(v, "name")?;
    if !name.contains('|') || name.as_bytes().get(1).is_none_or(|b| *b != b'.') {
        return Err(ApiError(400, "The client must encrypt the item name"));
    }
    Ok(())
}
fn validate_cipher(p: &Value, u: &User) -> ApiResult<()> {
    if !p.is_object() {
        return Err(ApiError(400, "Invalid item"));
    }
    encrypted_name(p)?;
    for key in ["organizationId", "organizationID", "attachments", "attachments2", "collectionIds"] {
        let v = &p[key];
        if !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty()) && v.as_object().is_none_or(|a| !a.is_empty()) {
            return Err(ApiError(400, "Organizations, collections and attachments are unavailable"));
        }
    }
    if !p["encryptedFor"].is_null() && p["encryptedFor"] != u.id() {
        return Err(ApiError(400, "Item was encrypted for another account"));
    }
    if !p["encryptedByKeyId"].is_null() {
        return Err(ApiError(400, "Versioned account keys are unavailable"));
    }
    let kind = p["type"].as_i64().ok_or(ApiError(400, "Missing item type"))?;
    if !(1..=8).contains(&kind) {
        return Err(ApiError(400, "Unsupported item type"));
    }
    if p.to_string().len() > 512 * 1024 {
        return Err(ApiError(413, "An item cannot exceed 512 KiB"));
    }
    Ok(())
}
fn payload(mut p: Value) -> Value {
    for key in [
        "id",
        "creationDate",
        "revisionDate",
        "deletedDate",
        "archivedDate",
        "lastKnownRevisionDate",
        "object",
        "edit",
        "viewPassword",
        "permissions",
    ] {
        p.as_object_mut().unwrap().remove(key);
    }
    for key in [
        "notes",
        "key",
        "fields",
        "passwordHistory",
        "login",
        "secureNote",
        "card",
        "identity",
        "sshKey",
        "bankAccount",
        "driversLicense",
        "passport",
    ] {
        if p.get(key).is_none() {
            p[key] = Value::Null;
        }
    }
    if p.get("favorite").is_none() {
        p["favorite"] = json!(false);
    }
    if p.get("reprompt").is_none() {
        p["reprompt"] = json!(0);
    }
    p
}
async fn check_folder(env: &Env, u: &User, p: &Value) -> ApiResult<Value> {
    let fid = nullable(p, "folderId");
    if fid.is_null() {
        return Ok(fid);
    }
    let id = fid.as_str().filter(|v| !v.is_empty()).ok_or(ApiError(400, "Invalid folder"))?;
    get_folder(env, u, id).await?;
    Ok(fid)
}
fn folder_guard(u: &User, id: Value) -> db::Statement {
    db::assertion(
        "SELECT CASE WHEN ? IS NULL THEN 1 ELSE (SELECT COUNT(*) FROM folders WHERE id=? AND user_id=?) END",
        vec![id.clone(), id, u.id()],
    )
}
fn item_guard(u: &User, id: &str, revision: &Value) -> db::Statement {
    db::assertion(
        "SELECT COUNT(*) FROM ciphers WHERE user_id=? AND id=? AND (? IS NULL OR revision=?)",
        vec![u.id(), json!(id), revision.clone(), revision.clone()],
    )
}
async fn save_cipher(env: &Env, u: &User, id: Option<&str>, p: Value, partial: bool) -> ApiResult<Response> {
    let existing = if let Some(id) = id {
        Some(get_cipher(env, u, id).await?)
    } else {
        None
    };
    let provided_revision = nullable(&p, "lastKnownRevisionDate");
    let data = if partial {
        let mut full: Value = serde_json::from_str(required(existing.as_ref().unwrap(), "payload")?)?;
        full["folderId"] = nullable(&p, "folderId");
        full["favorite"] = p["favorite"].clone();
        full
    } else {
        p
    };
    validate_cipher(&data, u)?;
    let fid = check_folder(env, u, &data).await?;
    let id = id.map(str::to_owned).unwrap_or_else(random_id);
    let rev = existing.as_ref().map(|r| next_date(text(r, "revision"))).unwrap_or_else(date);
    let mut queries = vec![folder_guard(u, fid.clone())];
    if let Some(record) = &existing {
        queries.push(item_guard(u, &id, &provided_revision));
        queries.push(item_guard(u, &id, &record["revision"]));
        queries.push((
            "UPDATE ciphers SET folder_id=?,payload=?,revision=? WHERE id=? AND user_id=?".into(),
            vec![fid, json!(payload(data).to_string()), json!(rev), json!(id), u.id()],
        ));
    } else {
        queries.push((
            "INSERT INTO ciphers(id,user_id,folder_id,payload,created,revision) VALUES(?,?,?,?,?,?)".into(),
            vec![json!(id), u.id(), fid, json!(payload(data).to_string()), json!(rev), json!(rev)],
        ));
    }
    db::write(env, u, queries).await?;
    response(cipher(get_cipher(env, u, &id).await?)?)
}
async fn save_folder(env: &Env, u: &User, requested: Option<&str>, p: Value) -> ApiResult<Response> {
    encrypted_name(&p)?;
    let id = requested.map(str::to_owned).unwrap_or_else(random_id);
    let queries = if let Some(id) = requested {
        let existing = get_folder(env, u, id).await?;
        vec![
            db::assertion(
                "SELECT COUNT(*) FROM folders WHERE id=? AND user_id=? AND revision=?",
                vec![json!(id), u.id(), existing["revision"].clone()],
            ),
            (
                "UPDATE folders SET name=?,revision=? WHERE id=? AND user_id=?".into(),
                vec![p["name"].clone(), json!(next_date(text(&existing, "revision"))), json!(id), u.id()],
            ),
        ]
    } else {
        vec![(
            "INSERT INTO folders(id,user_id,name,revision) VALUES(?,?,?,?)".into(),
            vec![json!(id), u.id(), p["name"].clone(), json!(date())],
        )]
    };
    db::write(env, u, queries).await?;
    response(folder(get_folder(env, u, &id).await?))
}
fn ids(p: &Value) -> ApiResult<Vec<Value>> {
    let values = p["ids"].as_array().ok_or(ApiError(400, "Missing item ids"))?;
    if values.is_empty() || values.len() > 1000 {
        return Err(ApiError(400, "Select between 1 and 1000 items"));
    }
    let mut unique = HashSet::new();
    for id in values {
        if !id.as_str().is_some_and(|v| !v.is_empty() && unique.insert(v)) {
            return Err(ApiError(400, "Invalid or duplicate item id"));
        }
    }
    Ok(values.clone())
}
async fn bulk(env: &Env, u: &User, p: Value, action: &str) -> ApiResult<Response> {
    let selected = ids(&p)?;
    let encoded = json!(selected).to_string();
    let mut queries = vec![db::assertion(
        "SELECT COUNT(*)=? FROM ciphers WHERE user_id=? AND id IN (SELECT value FROM json_each(?))",
        vec![json!(selected.len()), u.id(), json!(encoded)],
    )];
    let sql = match action {
        "delete" => {
            "UPDATE ciphers SET deleted=?,revision=? WHERE user_id=? AND id IN (SELECT value FROM json_each(?))"
        }
        "restore" => {
            "UPDATE ciphers SET deleted=NULL,revision=? WHERE user_id=? AND id IN (SELECT value FROM json_each(?))"
        }
        "archive" => {
            "UPDATE ciphers SET archived=?,revision=? WHERE user_id=? AND id IN (SELECT value FROM json_each(?))"
        }
        "unarchive" => {
            "UPDATE ciphers SET archived=NULL,revision=? WHERE user_id=? AND id IN (SELECT value FROM json_each(?))"
        }
        "permanent" => "DELETE FROM ciphers WHERE user_id=? AND id IN (SELECT value FROM json_each(?))",
        "move" => {
            "UPDATE ciphers SET folder_id=?,revision=? WHERE user_id=? AND id IN (SELECT value FROM json_each(?))"
        }
        _ => return Err(ApiError(400, "Invalid bulk action")),
    };
    let mut args = vec![];
    if matches!(action, "delete" | "archive") {
        args.push(json!(date()));
    }
    if action == "move" {
        let fid = check_folder(env, u, &p).await?;
        queries.push(folder_guard(u, fid.clone()));
        args.push(fid);
    }
    if action != "permanent" {
        args.push(json!(date()));
    }
    args.extend([u.id(), json!(encoded)]);
    queries.push((sql.into(), args));
    db::write(env, u, queries).await?;
    if matches!(action, "restore" | "archive" | "unarchive") {
        let updated = db::all(
            env,
            "SELECT * FROM ciphers WHERE user_id=? AND id IN (SELECT value FROM json_each(?))",
            &[u.id(), json!(encoded)],
        )
        .await?
        .into_iter()
        .map(cipher)
        .collect::<ApiResult<Vec<_>>>()?;
        return response(list(updated));
    }
    empty()
}
async fn import(env: &Env, u: &User, p: Value) -> ApiResult<Response> {
    if !p["organizationId"].is_null() || p["collections"].as_array().is_some_and(|a| !a.is_empty()) {
        return Err(ApiError(400, "Organization imports are unavailable"));
    }
    let items = p["ciphers"].as_array().ok_or(ApiError(400, "Missing import items"))?;
    let dirs = p["folders"].as_array().cloned().unwrap_or_default();
    if items.len() + dirs.len() > 1000 {
        return Err(ApiError(413, "Import at most 1000 records per request"));
    }
    let rev = date();
    let mut folder_rows = vec![];
    for f in &dirs {
        encrypted_name(f)?;
        folder_rows.push(json!({"id":random_id(),"name":f["name"]}));
    }
    let mut mapping = vec![Value::Null; items.len()];
    if let Some(relations) = p["folderRelationships"].as_array() {
        for r in relations {
            let ci = r["key"].as_u64().ok_or(ApiError(400, "Invalid import mapping"))? as usize;
            let fi = r["value"].as_u64().ok_or(ApiError(400, "Invalid import mapping"))? as usize;
            if ci >= items.len() || fi >= dirs.len() || !mapping[ci].is_null() {
                return Err(ApiError(400, "Invalid or duplicate import mapping"));
            }
            mapping[ci] = folder_rows[fi]["id"].clone();
        }
    }
    let mut rows = vec![];
    for (index, item) in items.iter().enumerate() {
        validate_cipher(item, u)?;
        if !item["folderId"].is_null() {
            return Err(ApiError(400, "Use import folder relationships"));
        }
        rows.push(json!({"id":random_id(),"folder":mapping[index],"payload":payload(item.clone()).to_string()}));
    }
    let folder_json = json!(folder_rows).to_string();
    let item_json = json!(rows).to_string();
    if folder_json.len() > 900_000 || item_json.len() > 900_000 {
        return Err(ApiError(413, "Split the encrypted import into smaller requests"));
    }
    let queries=vec![
        ("INSERT INTO folders(id,user_id,name,revision) SELECT json_extract(value,'$.id'),?,json_extract(value,'$.name'),? FROM json_each(?)".into(),vec![u.id(),json!(rev),json!(folder_json)]),
        ("INSERT INTO ciphers(id,user_id,folder_id,payload,created,revision) SELECT json_extract(value,'$.id'),?,json_extract(value,'$.folder'),json_extract(value,'$.payload'),?,? FROM json_each(?)".into(),vec![u.id(),json!(rev),json!(rev),json!(item_json)])
    ];
    db::write(env, u, queries).await?;
    empty()
}
async fn change_password(req: &mut Request, env: &Env, u: &User) -> ApiResult<Response> {
    auth::throttle(req, env, "password", 10).await?;
    let p = body(req).await?;
    auth::check_password(u, env, required(&p, "masterPasswordHash")?).await?;
    let a = &p["authenticationData"];
    let unlock = &p["unlockData"];
    let (hash, key, params) = if a.is_object() && unlock.is_object() {
        if a["kdf"] != unlock["kdf"] || a["salt"] != u.data["kdf_salt"] || unlock["salt"] != u.data["kdf_salt"] {
            return Err(ApiError(400, "Invalid authentication or unlock parameters"));
        }
        (
            required(a, "masterPasswordAuthenticationHash")?,
            required(unlock, "masterKeyWrappedUserKey")?,
            auth::kdf(&a["kdf"])?,
        )
    } else {
        if req.path().ends_with("/kdf") {
            return Err(ApiError(400, "KDF changes require authentication and unlock data"));
        }
        (
            required(&p, "newMasterPasswordHash")?,
            required(&p, "key")?,
            (
                u.data["kdf"].clone(),
                u.data["iterations"].clone(),
                u.data["memory"].clone(),
                u.data["parallelism"].clone(),
            ),
        )
    };
    if req.path().ends_with("/password")
        && params
            != (
                u.data["kdf"].clone(),
                u.data["iterations"].clone(),
                u.data["memory"].clone(),
                u.data["parallelism"].clone(),
            )
    {
        return Err(ApiError(400, "Use the KDF endpoint to change derivation parameters"));
    }
    let salt = random_secret().replace('-', "+").replace('_', "/");
    let verifier = auth::verifier(env, &u.data, hash, &salt).await?;
    let (kind, it, memory, parallelism) = params;
    db::write(env,u,vec![("UPDATE users SET verifier=?,salt=?,wrapped_key=?,hint=?,kdf=?,iterations=?,memory=?,parallelism=?,stamp=? WHERE id=?".into(),vec![json!(verifier),json!(salt),json!(key),nullable(&p,"masterPasswordHint"),kind,it,memory,parallelism,json!(random_id()),u.id()]),("DELETE FROM sessions WHERE user_id=?".into(),vec![u.id()])]).await?;
    empty()
}
pub async fn route(req: &mut Request, env: &Env, u: &User) -> ApiResult<Response> {
    let path = req.path();
    let method = req.method();
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    let write = matches!(method, Method::Post | Method::Put | Method::Delete);
    // Stock SSO's first-password flow requests these two compatibility records.
    // This virtual identifier confers no organization membership or recovery access.
    if path == "/api/organizations/hasbai/auto-enroll-status" && method == Method::Get {
        return response(
            json!({"id":"00000000-01dc-01dc-01dc-000000000000","identifier":"hasbai","resetPasswordEnabled":false,"object":"organizationAutoEnrollStatus"}),
        );
    }
    if path == "/api/organizations/00000000-01dc-01dc-01dc-000000000000/policies/master-password"
        && method == Method::Get
    {
        return response(json!({"enabled":false,"type":0,"data":null,"object":"policy"}));
    }
    if path == "/api/accounts/set-password" && method == Method::Post {
        if !text(&u.data, "wrapped_key").is_empty() || !u.data["verifier"].is_null() {
            return Err(ApiError(409, "Vault is already initialized"));
        }
        auth::account_throttle(u, env).await?;
        let p = body(req).await?;
        let (kind, it, memory, parallelism) = auth::kdf(&p)?;
        let key = required(&p, "key")?;
        let hash = required(&p, "masterPasswordHash")?;
        let salt = random_secret().replace('-', "+").replace('_', "/");
        let verifier = auth::verifier(env, &u.data, hash, &salt).await?;
        let private = required(&p["keys"], "encryptedPrivateKey")?;
        let public = required(&p["keys"], "publicKey")?;
        db::write(env,u,vec![db::assertion("SELECT COUNT(*) FROM users WHERE id=? AND wrapped_key='' AND verifier IS NULL",vec![u.id()]),("UPDATE users SET verifier=?,salt=?,wrapped_key=?,private_key=?,public_key=?,kdf=?,iterations=?,memory=?,parallelism=?,hint=? WHERE id=?".into(),vec![json!(verifier),json!(salt),json!(key),json!(private),json!(public),kind,it,memory,parallelism,nullable(&p,"masterPasswordHint"),u.id()])]).await?;
        return response(json!({"object":"set-password"}));
    }
    if text(&u.data, "wrapped_key").is_empty() && method != Method::Get {
        return Err(ApiError(409, "Initialize the encrypted vault first"));
    }
    if path == "/api/sync" && method == Method::Get {
        let dirs = folders(env, u).await?;
        let items = ciphers(env, u).await?;
        return response(
            json!({"profile":u.profile(),"folders":dirs,"collections":[],"policies":[],"policiesNew":[],"ciphers":items,"domains":domains(u)?,"sends":[],"userDecryption":{"masterPasswordUnlock":u.unlock(false),"userKeyId":null},"object":"sync"}),
        );
    }
    if path == "/api/accounts/revision-date" && method == Method::Get {
        return response(u.data["revision"].clone());
    }
    if path == "/api/accounts/profile" {
        if method == Method::Get {
            return response(u.profile());
        }
        if write {
            return Err(ApiError(403, "Manage identity through Auth0"));
        }
    }
    if path == "/api/accounts/avatar" && method == Method::Put {
        let p = body(req).await?;
        db::write(
            env,
            u,
            vec![("UPDATE users SET avatar=? WHERE id=?".into(), vec![nullable(&p, "avatarColor"), u.id()])],
        )
        .await?;
        return empty();
    }
    if path == "/api/accounts/keys" {
        if method == Method::Get {
            return response(
                json!({"privateKey":u.data["private_key"],"publicKey":u.data["public_key"],"object":"keys"}),
            );
        }
        if method == Method::Post {
            if !u.data["private_key"].is_null() {
                return Err(ApiError(409, "Account key rotation is unavailable"));
            }
            let p = body(req).await?;
            db::write(
                env,
                u,
                vec![
                    db::assertion("SELECT COUNT(*) FROM users WHERE id=? AND private_key IS NULL", vec![u.id()]),
                    (
                        "UPDATE users SET private_key=?,public_key=? WHERE id=?".into(),
                        vec![json!(required(&p, "encryptedPrivateKey")?), json!(required(&p, "publicKey")?), u.id()],
                    ),
                ],
            )
            .await?;
            return empty();
        }
    }
    if matches!(path.as_str(), "/api/accounts/password" | "/api/accounts/kdf") && method == Method::Post {
        return change_password(req, env, u).await;
    }
    if path == "/api/accounts/verify-password" && method == Method::Post {
        auth::throttle(req, env, "password", 10).await?;
        let p = body(req).await?;
        auth::check_password(u, env, required(&p, "masterPasswordHash")?).await?;
        return empty();
    }
    if path == "/api/accounts/security-stamp" && method == Method::Post {
        let p = body(req).await?;
        auth::check_password(u, env, required(&p, "masterPasswordHash")?).await?;
        db::write(
            env,
            u,
            vec![
                ("UPDATE users SET stamp=? WHERE id=?".into(), vec![json!(random_id()), u.id()]),
                ("DELETE FROM sessions WHERE user_id=?".into(), vec![u.id()]),
            ],
        )
        .await?;
        return empty();
    }
    if path == "/api/settings/domains" {
        if method == Method::Get {
            return response(domains(u)?);
        }
        if matches!(method, Method::Post | Method::Put) {
            let p = body(req).await?;
            if !p["equivalentDomains"].is_array() || !p["excludedGlobalEquivalentDomains"].is_array() {
                return Err(ApiError(400, "Invalid domain settings"));
            }
            db::write(
                env,
                u,
                vec![(
                    "UPDATE users SET domains=?,excluded_domains=? WHERE id=?".into(),
                    vec![
                        json!(p["equivalentDomains"].to_string()),
                        json!(p["excludedGlobalEquivalentDomains"].to_string()),
                        u.id(),
                    ],
                )],
            )
            .await?;
            return empty();
        }
    }
    if path == "/api/folders" {
        if method == Method::Get {
            return response(list(folders(env, u).await?));
        }
        if method == Method::Post {
            return save_folder(env, u, None, body(req).await?).await;
        }
    }
    if parts.get(1) == Some(&"folders") && parts.len() >= 3 {
        let id = parts[2];
        get_folder(env, u, id).await?;
        if method == Method::Get && parts.len() == 3 {
            return response(folder(get_folder(env, u, id).await?));
        }
        if matches!(method, Method::Put | Method::Post) && parts.len() == 3 {
            return save_folder(env, u, Some(id), body(req).await?).await;
        }
        if method == Method::Delete || (method == Method::Post && parts.get(3) == Some(&"delete")) {
            db::write(
                env,
                u,
                vec![
                    (
                        "UPDATE ciphers SET folder_id=NULL,revision=? WHERE folder_id=? AND user_id=?".into(),
                        vec![json!(date()), json!(id), u.id()],
                    ),
                    ("DELETE FROM folders WHERE id=? AND user_id=?".into(), vec![json!(id), u.id()]),
                ],
            )
            .await?;
            return empty();
        }
    }
    if path == "/api/ciphers" {
        if method == Method::Get {
            return response(list(ciphers(env, u).await?));
        }
        if method == Method::Post {
            return save_cipher(env, u, None, body(req).await?, false).await;
        }
        if method == Method::Delete {
            return bulk(env, u, body(req).await?, "permanent").await;
        }
    }
    if path == "/api/ciphers/create" && method == Method::Post {
        let p = body(req).await?;
        if p["collectionIds"].as_array().is_some_and(|a| !a.is_empty()) {
            return Err(ApiError(400, "Collections are unavailable"));
        }
        return save_cipher(env, u, None, p["cipher"].clone(), false).await;
    }
    if path == "/api/ciphers/import" && method == Method::Post {
        return import(env, u, body(req).await?).await;
    }
    if path == "/api/ciphers/purge" && matches!(method, Method::Post | Method::Put) {
        let p = body(req).await?;
        auth::check_password(u, env, required(&p, "masterPasswordHash")?).await?;
        db::write(
            env,
            u,
            vec![
                ("DELETE FROM ciphers WHERE user_id=?".into(), vec![u.id()]),
                ("DELETE FROM folders WHERE user_id=?".into(), vec![u.id()]),
            ],
        )
        .await?;
        return empty();
    }
    if parts.get(1) == Some(&"ciphers")
        && parts.len() == 3
        && write
        && matches!(parts[2], "delete" | "restore" | "move" | "archive" | "unarchive")
    {
        let action = if parts[2] == "delete" && method == Method::Post {
            "permanent"
        } else {
            parts[2]
        };
        return bulk(env, u, body(req).await?, action).await;
    }
    if parts.get(1) == Some(&"ciphers") && parts.len() >= 3 {
        let id = parts[2];
        let row = get_cipher(env, u, id).await?;
        if method == Method::Get && (parts.len() == 3 || parts.get(3) == Some(&"details")) {
            return response(cipher(row)?);
        }
        if matches!(method, Method::Put | Method::Post) && (parts.len() == 3 || parts.get(3) == Some(&"partial")) {
            return save_cipher(env, u, Some(id), body(req).await?, parts.get(3) == Some(&"partial")).await;
        }
        let action = if (method == Method::Delete && parts.len() == 3)
            || (method == Method::Post && parts.get(3) == Some(&"delete"))
        {
            "permanent"
        } else if write {
            parts.get(3).copied().unwrap_or("")
        } else {
            ""
        };
        if matches!(action, "permanent" | "delete" | "restore" | "archive" | "unarchive") {
            let result = bulk(env, u, json!({"ids":[id]}), action).await?;
            if matches!(action, "restore" | "archive" | "unarchive") {
                return response(cipher(get_cipher(env, u, id).await?)?);
            }
            return Ok(result);
        }
    }
    if path == "/api/devices" && method == Method::Get {
        let data=db::all(env,"SELECT * FROM sessions WHERE user_id=?",&[u.id()]).await?.into_iter().map(|s|json!({"id":s["id"],"identifier":s["device_id"],"name":s["device_name"],"type":s["device_type"],"creationDate":iso_date(s["created"].as_f64().unwrap_or(0.0)*1000.0),"object":"device"})).collect();
        return response(list(data));
    }
    if parts.get(1) == Some(&"devices") && parts.len() == 3 && method == Method::Delete {
        db::write(
            env,
            u,
            vec![("DELETE FROM sessions WHERE id=? AND user_id=?".into(), vec![json!(parts[2]), u.id()])],
        )
        .await?;
        return empty();
    }
    if matches!(
        path.as_str(),
        "/api/collections"
            | "/api/organizations"
            | "/api/sends"
            | "/api/two-factor"
            | "/api/accounts/webauthn"
            | "/api/accounts/known-devices"
            | "/api/auth-requests/pending"
            | "/api/emergency-access/trusted"
            | "/api/emergency-access/granted"
    ) && method == Method::Get
    {
        return response(list(vec![]));
    }
    if path == "/api/accounts/delete" && method == Method::Post {
        return Err(ApiError(501, "Account deletion requires an operator; registration remains closed"));
    }
    Err(ApiError(501, "Feature is unavailable in the personal Worker"))
}
fn domains(u: &User) -> ApiResult<Value> {
    let equivalent: Value = serde_json::from_str(text(&u.data, "domains"))?;
    let excluded: Value = serde_json::from_str(text(&u.data, "excluded_domains"))?;
    Ok(
        json!({"equivalentDomains":equivalent,"globalEquivalentDomains":[],"excludedGlobalEquivalentDomains":excluded,"object":"domains"}),
    )
}
