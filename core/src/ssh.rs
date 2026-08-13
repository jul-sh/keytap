pub fn public_key_line(seed: &[u8; 32], name: Option<&str>) -> String {
    let vk = crate::ed25519::public_key(seed);
    let key = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey::from(vk));
    let openssh = key.to_openssh().unwrap();
    let comment = match name {
        Some(name) => format!("keytap:{name}"),
        None => "keytap".to_string(),
    };
    format!("{openssh} {comment}")
}

pub fn private_key_pem(seed: &[u8; 32]) -> String {
    let keypair = ssh_key::private::Ed25519Keypair::from_seed(seed);
    ssh_key::PrivateKey::from(keypair)
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap()
        .to_string()
}
