use std::time::SystemTime;
use lambda_runtime::LambdaEvent;

use super::request::Request;
use super::response::Response;
use super::Error;

#[tracing::instrument(skip(s3_client, event), fields(req_id = %event.context.request_id))]
pub async fn put_object(
    s3_client: &aws_sdk_s3::Client,
    bucket_name: &str,
    event: LambdaEvent<Request>,
) -> Result<Response, Error> {
    tracing::info!("handling a request");
    // Generate a filename based on when the request was received.
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|n| n.as_secs())
        .expect("SystemTime before UNIX EPOCH, clock might have gone backwards");

    let filename = format!("{timestamp}.txt");
    let response = s3_client
        .put_object()
        .bucket(bucket_name)
        .body(event.payload.body.as_bytes().to_owned().into())
        .key(&filename)
        .content_type("text/plain")
        .send()
        .await;

    match response {
        Ok(_) => {
            tracing::info!(
                filename = %filename,
                "data successfully stored in S3",
            );
            // Return `Response` (it will be serialized to JSON automatically by the runtime)
            Ok(Response {
                req_id: event.context.request_id,
                body: format!(
                    "the Lambda function has successfully stored your data in S3 with name '{filename}'"
                ),
            })
        }
        Err(err) => {
            // In case of failure, log a detailed error to CloudWatch.
            tracing::error!(
                err = %err,
                filename = %filename,
                "failed to upload data to S3"
            );
            Err(Box::new(Response {
                req_id: event.context.request_id,
                body: "The Lambda function encountered an error and your data was not saved"
                    .to_owned(),
            }))
        }
    }
}
