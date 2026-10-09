use crate::*;
pub type Statement = (String, Vec<Value>);
fn binding(v: &Value) -> JsValue {
    match v {
        Value::Null => JsValue::NULL,
        Value::Bool(v) => JsValue::from_f64(if *v {
            1.0
        } else {
            0.0
        }),
        Value::Number(v) => JsValue::from_f64(v.as_f64().unwrap_or(0.0)),
        Value::String(v) => JsValue::from_str(v),
        _ => JsValue::from_str(&v.to_string()),
    }
}
pub fn statement(db: &D1Database, sql: &str, args: &[Value]) -> ApiResult<D1PreparedStatement> {
    Ok(db.prepare(sql).bind(&args.iter().map(binding).collect::<Vec<_>>())?)
}
pub async fn one(env: &Env, sql: &str, args: &[Value]) -> ApiResult<Option<Value>> {
    Ok(statement(&env.d1("DB")?, sql, args)?.first::<Value>(None).await?)
}
pub async fn all(env: &Env, sql: &str, args: &[Value]) -> ApiResult<Vec<Value>> {
    Ok(statement(&env.d1("DB")?, sql, args)?.all().await?.results::<Value>()?)
}
pub async fn batch(env: &Env, queries: Vec<Statement>) -> ApiResult<()> {
    let db = env.d1("DB")?;
    let prepared = queries.iter().map(|(sql, args)| statement(&db, sql, args)).collect::<ApiResult<Vec<_>>>()?;
    db.batch(prepared).await?;
    Ok(())
}
pub fn assertion(sql: &str, args: Vec<Value>) -> Statement {
    (format!("INSERT INTO transaction_guard(valid) VALUES(COALESCE(({sql}),0))"), args)
}
pub async fn write(env: &Env, user: &auth::User, mut queries: Vec<Statement>) -> ApiResult<()> {
    let mut batch = vec![assertion(
        "SELECT COUNT(*) FROM users u JOIN sessions s ON s.user_id=u.id WHERE u.id=? AND u.stamp=? AND s.id=? AND s.stamp=u.stamp AND s.expires>?",
        vec![user.id(), user.stamp(), json!(user.session), json!(time_ms() / 1000)],
    )];
    batch.append(&mut queries);
    batch.push(("UPDATE users SET revision=MAX(revision+1,?) WHERE id=?".into(), vec![json!(time_ms()), user.id()]));
    batch.push(("DELETE FROM transaction_guard".into(), vec![]));
    // A failed assertion rolls back all mutations, including revision changes.
    batch_result(env, batch).await
}
pub async fn batch_result(env: &Env, queries: Vec<Statement>) -> ApiResult<()> {
    batch(env, queries).await.map_err(|_| ApiError(409, "Concurrent change detected; sync and retry"))
}
