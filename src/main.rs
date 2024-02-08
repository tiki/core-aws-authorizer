use aws_config::BehaviorVersion;
use lambda_runtime::{service_fn, Error, LambdaEvent};

mod request;
use request::Request;
mod put_object;
mod response;
use put_object::put_object;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();

    let bucket_name = std::env::var("BUCKET_NAME")
        .expect("A BUCKET_NAME must be set in this app's Lambda environment variables.");

    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let s3_client = aws_sdk_s3::Client::new(&config);

    lambda_runtime::run(service_fn(|event: LambdaEvent<Request>| async {
        put_object(&s3_client, &bucket_name, event).await
    }))
    .await
}
