use anyhow::Result;
use argon2::{password_hash::{
	rand_core::OsRng,
	PasswordHasher, SaltString
}, Argon2};


pub fn create_password(password: &str) -> Result<String> {
	let salt = SaltString::generate(&mut OsRng);
	let argon = Argon2::default();
	argon.hash_password(password.as_bytes(), &salt)
		.map(|x| x.to_string()).map_err(|x| x.into())
}