use super::AuthAPIError;
use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};

// The User struct should contain 3 fields. email, which is a String; 
// password, which is also a String; and requires_2fa, which is a boolean. 
#[derive(Clone, Debug, PartialEq)]
pub struct User {
    pub email: Email,
    pub password: Password,
    pub requires_2fa: bool
}

impl User {
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> Self {
        User { email, password, requires_2fa }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Email> {
        if !email.is_empty() && email.contains('@') {
            Ok(Email(email))
        } else {
            Err(AuthAPIError::InvalidCredentials)?
        }
    }
}

// Implement the AsRef trait for Email
impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}


#[derive(Debug, Clone)] // Updated!
pub struct Password(Secret<String>); // Updated!

impl PartialEq for Password { // New!
    fn eq(&self, other: &Self) -> bool {
        // We can use the expose_secret method to expose the secret in a
        // controlled manner when needed!
        self.0.expose_secret() == other.0.expose_secret() // Updated!
    }
}

impl Password {
    pub fn parse(s: Secret<String>) -> Result<Password> { // Updated!
        if validate_password(&s) {
            Ok(Self(s))
        } else {
            Err(eyre!("Failed to parse string to a Password type"))
        }
    }
}

fn validate_password(s: &Secret<String>) -> bool { // Updated!
    s.expose_secret().len() >= 8
}

impl AsRef<Secret<String>> for Password { // Updated!
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}


#[cfg(test)]
mod tests {
    use super::Password;

    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use secrecy::Secret; // New!

    #[test]
    fn empty_string_is_rejected() {
        let password = Secret::new("".to_string()); // Updated!
        assert!(Password::parse(password).is_err());
    }
    #[test]
    fn string_less_than_8_characters_is_rejected() {
        let password = Secret::new("1234567".to_string()); // Updated!
        assert!(Password::parse(password).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub Secret<String>); // Updated!

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            let password = FakePassword(8..30).fake_with_rng(g);
            Self(Secret::new(password)) // Updated!
        }
    }
    #[quickcheck_macros::quickcheck]
    fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        Password::parse(valid_password.0).is_ok()
    }
}