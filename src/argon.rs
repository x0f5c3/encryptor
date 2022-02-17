use anyhow::Result;
use argon2::{password_hash::{
	rand_core::OsRng,
	PasswordHasher, PasswordVerifier, SaltString
}, Argon2, Algorithm, Params};
use argon2::Version::V0x13;


pub fn create_password(password: &str) -> Result<String> {
	let salt = SaltString::generate(&mut OsRng);
	let argon = Argon2::new(Algorithm::Argon2id, V0x13, Params::default());
	argon.hash_password(password.as_bytes(), &salt)
		.map(|x| x.to_string()).into()
}