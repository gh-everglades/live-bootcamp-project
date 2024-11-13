use crate::domain::{Email, EmailClient};
use color_eyre::eyre::Result;
pub struct MockEmailClient;
use secrecy::ExposeSecret;

#[async_trait::async_trait]
impl EmailClient for MockEmailClient {
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<()> {
        // Our mock email client will simply log the recipient, subject, and content to standard output
        tracing::debug!(
            "Sending email to {} with subject: {} and content: {}",
            recipient.expose_secret(),
            subject,
            content
        );

        Ok(())
    }
}