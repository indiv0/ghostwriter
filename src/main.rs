fn main() -> Result<(), ureq::Error> {
    // Read the AI API key from the environment.
    let api_key = match std::env::var("API_KEY") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("set your API_KEY");
            return Ok(());
        }
    };

    // Request a code completion from the AI API.
    let body = ureq::post("https://api.goose.ai/v1/engines/gpt-neo-20b/completions")
        .set("Authorization", &format!("Bearer {}", api_key))
        .send_json(ureq::json!({
            "prompt": "Say this is a test",
            "max_tokens": 6,
        }))?
        .into_string()?;
    println!("body: {}", body);
    Ok(())
}
