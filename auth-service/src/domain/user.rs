use super::AuthAPIError;

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
#[derive(Clone, Debug, PartialEq)]
pub struct Password(String);
impl Email {
    pub fn parse(email: String) -> Result<Email, AuthAPIError> {
        if !email.is_empty() && email.contains('@') {
            Ok(Email(email))
        } else {
            Err(AuthAPIError::InvalidCredentials)
        }
    }
}

// Implement the AsRef trait for Email
impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}


impl Password {
    pub fn parse(password: String) -> Result<Password, AuthAPIError> {
        if password.len() >= 8 {
            Ok(Password(password))
        } else {
            Err(AuthAPIError::InvalidCredentials)
        }
    }
}

// Implement the AsRef trait for Password
impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}