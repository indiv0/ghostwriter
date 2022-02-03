use std::{
    borrow::Cow,
    time::{Duration, Instant},
};

use serenity::{
    async_trait,
    client::{Context, EventHandler},
    model::{channel::Message, prelude::Ready},
    prelude::TypeMapKey,
    utils::{content_safe, ContentSafeOptions},
    Client,
};
use ureq::serde_json::Value;

// --------------------------------------------------------------------------
// Application Entrypoint
// --------------------------------------------------------------------------

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), ureq::Error> {
    // Read the AI API key from the environment.
    let api_key = std::env::var("API_KEY").expect("expected API_KEY");
    // Read the Discord bot token from the environment.
    let token = std::env::var("DISCORD_TOKEN").expect("expected DISCORD_TOKEN");

    // Create a new instance of the `Client`, logging in as a bot. This will
    // automatically prepend your bot token with "Bot ", which is a
    // requirement by Discord for bot users.
    println!("creating client");
    let mut client = Client::builder(&token)
        .event_handler(Handler { api_key })
        .await
        .expect("error creating client");

    {
        // Insert shared data into the `Client` `ShareMap`. Currently this is
        // a single global rate limit counter.
        let mut data = client.data.write().await;
        data.insert::<RateLimitKey>(RateLimit::default());
    }

    // Finally, start a single shard, and start listening to events.
    //
    // Shards will automatically attempt to reconnect, and will perform
    // exponential backoff until it reconnects.
    println!("starting shard");
    if let Err(why) = client.start().await {
        println!("client error: {:?}", why);
    }

    Ok(())
}

// --------------------------------------------------------------------------
// Discord Event Handler
// --------------------------------------------------------------------------

/// Handler for discord events.
struct Handler {
    /// API key used to make AI prompt requests.
    api_key: String,
}

#[async_trait]
impl EventHandler for Handler {
    // Set a handler for the `message` event - so that whenever a new message
    // is recieved - the closure (or function) passed will be called.
    //
    // Event handlers are dispatched through a threadpool, and so multiple
    // events can be dispatched simultaneously.
    async fn message(&self, ctx: Context, msg: Message) {
        // Try to process the message as command, and if that succeeds send
        // the reply to the user.
        if let Some(reply) = self.message_(&ctx, &msg).await {
            // Sending a message can fail, due to a network error, an
            // authentication error, or lack of permissions to post in the
            // channel, so log to stdout when some error happens, with a
            // description of it.
            if let Err(why) = msg.channel_id.say(&ctx.http, reply).await {
                eprintln!("error sending message: {:?}", why);
            }
        }
    }

    // Set a handler to be called on the `ready` event. This is called when a
    // shard is booted, and a READY payload is sent by Discord. This payload
    // contains data like the current user's guild IDs, current user data,
    // private channels, and more.
    //
    // In this case, just print what the current user's username is.
    async fn ready(&self, _: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);
    }
}

impl Handler {
    // Processes the message, and if the message is recognized as a command
    // the command is handled and a response is return that can be sent to
    // the user.
    async fn message_(&self, ctx: &Context, msg: &Message) -> Option<Cow<'_, str>> {
        if msg.content == "!ping" {
            return Some(Cow::Borrowed("Pong!"));
        } else if msg.content.starts_with("!smprompt") && msg.author.id == 117530756263182344 {
            // Strip the command part of the message, leaving just the prompt
            // to the AI.
            let (_, prompt) = msg.content.split_once("!smprompt").unwrap();
            let prompt = prompt.trim_start();

            // If we didn't receive a prompt or received a prompt that was
            // just whitespace, tell the user that they need to include text
            // in the prompt.
            if prompt.is_empty() {
                return Some(Cow::Borrowed("usage: smprompt text"));
            }

            // Restrict the input to at most 200 characters to limit the
            // usage of API tokens.
            //if prompt.len() > 200 {
            //    return Some(Cow::Owned(format!(
            //        "prompt must be 200 characters or less; your prompt was {} character(s) too long",
            //        prompt.len() - 200,
            //    )));
            //}

            // Enforce a global rate limit of 60 requests per minute to avoid
            // spam from overwhelming the bot OR overwhelming the AI API.
            // Check to see if this command is rate limited.
            if let Some(remaining) = ctx
                .data
                .write()
                .await
                .get_mut::<RateLimitKey>()
                .expect("expected RateLimit in ShareMap")
                .is_limited()
            {
                return Some(Cow::Owned(format!(
                    "rate limit of 60 requests per minute reached, please wait at least {} second(s) before trying again",
                    remaining
                )));
            }

            //// Request a code completion from the AI API.
            println!("user {} requested prompt: {}", msg.author.id.0, prompt);
            let body = match ureq::post("https://api.goose.ai/v1/engines/gpt-neo-20b/completions")
                .set("Authorization", &format!("Bearer {}", self.api_key))
                .send_json(ureq::json!({
                    "prompt": prompt,
                    "temperature": 0,  // Default 1
                    "max_tokens": 100, // Default 16
                    //"top_p": 1,        // Default 1
                    "stop": ["\n"],      // Default null
                })) {
                Ok(body) => body,
                Err(error) => {
                    eprint!("error requesting prompt: {:?}", error);
                    // If it's not a transport error, it'll have a body.
                    if let Some(body) = error.into_response().map(|r| r.into_string()) {
                        eprint!(": {:?}", body);
                    }
                    eprintln!();
                    return Some(Cow::Borrowed("prompt request failed"));
                }
            };
            print!("response: {:?}", body);
            // Read the response into a `serde_json::Value`.
            let body: Value = match body.into_json() {
                Ok(body) => body,
                Err(error) => {
                    eprintln!("error requesting prompt: {:?}", error);
                    return Some(Cow::Borrowed("prompt request failed"));
                }
            };
            println!(": {:?}", body);
            // Read the actual content of the response out of the JSON.
            //
            // ```json
            // {
            //   "choices": [
            //     {
            //       "finish_reason": null,
            //       "index": 0,
            //       "logprobs": {
            //         "text_offset": [0, 1, 2, 4, 5],
            //         "tokens": [
            //           ".",
            //           "bytes:'\\n'",
            //           "",
            //           "\u003c/",
            //           "p",
            //           "\u003e"
            //         ]
            //      },
            //      "text": ".\n\u003c/p\u003e",
            //      "token_index": 0
            //     }
            //   ],
            //   "created": 1643862189,
            //   "id": "2dfd25bc-9a8e-440d-a808-29494b3b30f6",
            //   "model": "gpt-neo-20B-fp16",
            //   "object": "text_completion"
            // }
            // ```
            let body = match body
                .get("choices")
                .and_then(|v| v.get(0))
                .and_then(|v| v.get("text"))
                .and_then(|v| v.as_str())
            {
                Some(body) => body,
                None => {
                    eprintln!("error parsing prompt: {:?}", body);
                    return Some(Cow::Borrowed("prompt request failed"));
                }
            };

            // Sanitize the response, because the user might've found a way
            // to XSS @mentions or other fun stuff into the response.
            let settings = if let Some(guild_id) = msg.guild_id {
                // Be default, roles, users, channel, here, and everyone
                // mentions are cleaned.
                ContentSafeOptions::default()
                    // We do not want to clean channel mentions as they do
                    // not ping users.
                    .clean_channel(false)
                    // If it's a guild channel, we want mentioned users to be
                    // displayed as their display name.
                    .display_as_member_from(guild_id)
            } else {
                ContentSafeOptions::default()
                    .clean_channel(false)
                    .clean_role(false)
            };
            let response = content_safe(&ctx.cache, &body, &settings).await;

            return Some(Cow::Owned(response));
        } else {
            // If the message wasn't a command, there's no reply to send.
            None
        }
    }
}

// --------------------------------------------------------------------------
// Rate Limiting
// --------------------------------------------------------------------------

/// Fixed window rate limiter.
struct RateLimit {
    expiry: Instant,
    count: usize,
}

impl RateLimit {
    // Logs a request with this rate limiter, and checks to see if we are
    // over the 60 request per minute limit.
    //
    // If we are over the limit, this function returns the minimum number
    // of seconds to wait before trying again.
    fn is_limited(&mut self) -> Option<usize> {
        // Check to see if we're past the point at which the window expires.
        let now = Instant::now();
        let expired = now > self.expiry;

        // Increment the internal counter.
        self.count += 1;

        // If the rate limit window has expired, reset the counter and set
        // the end time for this window to be 60 seconds in the future.
        if expired {
            self.expiry = now + Duration::from_secs(60);
            self.count = 1;
            // New window has started, so we're not at the rate limit.
            return None;
        }

        // If we haven't reached the limit of 60 requests in this minute,
        // then the request is allowed.
        if self.count <= 2 {
            return None;
        }

        // If we've hit the rate limit, return the minimum number of seconds
        // to wait before retrying.
        let remaining = self.expiry - now;
        let remaining = remaining.as_secs() as f64 + remaining.subsec_nanos() as f64 * 1e-9;
        let remaining = remaining.ceil();
        return Some(remaining as usize);
    }
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            expiry: Instant::now(),
            count: 0,
        }
    }
}

/// A helper struct for turning a type into a key. This lets us store
/// `RateLimit` instances in the client's shared data map.
struct RateLimitKey;

impl TypeMapKey for RateLimitKey {
    type Value = RateLimit;
}
