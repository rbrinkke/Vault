use service_secrets::{LoadedSecrets, SecretSpec};
use std::env;

fn parse_keys(var_name: &str) -> Vec<&'static str> {
    env::var(var_name)
        .ok()
        .map(|value| {
            value.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| Box::leak(value.to_string().into_boxed_str()) as &'static str)
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app_env = env::var("APP_ENV").unwrap_or_else(|_| "production".to_string());
    let required = parse_keys("REQUIRED_KEYS");
    let optional = parse_keys("OPTIONAL_KEYS");

    let mut specs: Vec<SecretSpec> = required
        .iter()
        .map(|key| SecretSpec::required(key))
        .collect();
    specs.extend(optional.iter().map(|key| SecretSpec::optional(key)));

    let secrets = LoadedSecrets::load(&specs, &app_env).await?;

    for key in &required {
        let _ = secrets.require_plain_string(key).await?;
        println!("{key}=present");
    }

    for key in &optional {
        let present = secrets.optional_plain_string(key).await?.is_some();
        println!("{key}={}", if present { "present" } else { "absent" });
    }

    Ok(())
}
