use axum::extract::Query;
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
pub struct DiagnosticQuery {
    target: String,
}

pub async fn diagnostics(Query(input): Query<DiagnosticQuery>) -> String {
    let argument = input.target;
    let output = Command::new("printf")
        .arg("%s")
        .arg(argument)
        .output()
        .expect("diagnostic command failed");
    String::from_utf8_lossy(&output.stdout).into_owned()
}
