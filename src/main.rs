use std::str::FromStr;

use anyhow::anyhow;
use bdk::{descriptor, KeychainKind};
use bdk::bitcoin::bip32::{ChildNumber, DerivationPath};
use bdk::bitcoin::Network;
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::descriptor::{Descriptor, IntoWalletDescriptor};
use bdk::keys::{DerivableKey, GeneratableKey, GeneratedKey};
use bdk::keys::bip39::{Language, Mnemonic, WordCount};
use bdk::miniscript::{Tap, ToPublicKey};
use bdk::template::{Bip86, DescriptorTemplate};

fn main() -> Result<(), anyhow::Error> {
    println!("> Generating a 12-word mnemonic");
    let mnemonic: GeneratedKey<_, Tap> =
        Mnemonic::generate((WordCount::Words12, Language::English))
            .map_err(|_| anyhow!("Mnemonic generation error"))?;
    println!("> Mnemonic phrase: {}", *mnemonic);
    let mnemonic_with_passphrase = (mnemonic, None);

    println!("define external and internal derivation key path");
    let external_path = DerivationPath::from_str("m/86h/1h/0h/0").unwrap();
    let internal_path = DerivationPath::from_str("m/86h/1h/0h/1").unwrap();

    println!("> BIP-44: m/purpose'/coin_type'/account'/change/address_index");
    println!("> here just m/purpose'/coin_type'/account'/change");
    println!("> external path: {}", external_path);
    println!("> internal path: {}", internal_path);

    println!("> generate external and internal descriptor from mnemonic");
    let secp = Secp256k1::new();
    println!("> secp: {:?}", secp);
    let (external_descriptor, ext_keymap) =
        descriptor!(tr((mnemonic_with_passphrase.clone(), external_path.clone())))?
            .into_wallet_descriptor(&secp, Network::Testnet)?;
    let (internal_descriptor, int_keymap) =
        descriptor!(tr((mnemonic_with_passphrase.clone(), internal_path)))?
            .into_wallet_descriptor(&secp, Network::Testnet)?;
    println!("> external descriptor: {}", external_descriptor);
    println!("> internal descriptor: {}", internal_descriptor);
    println!("> tprv external descriptor: {}", external_descriptor.to_string_with_secret(&ext_keymap));
    println!("> tprv internal descriptor: {}", internal_descriptor.to_string_with_secret(&int_keymap));

    println!("> create bip32 root key");
    let extended_key = mnemonic_with_passphrase.into_extended_key().unwrap();

    let xprv = extended_key.into_xprv(Network::Testnet).unwrap();
    println!("> extend_private_key: {} {:?}", xprv.to_string(), xprv);

    println!("> use bip86 to create external and internal descriptor, should same with above");
    let (external_descriptor, ext_keymap, _) = Bip86(xprv, KeychainKind::External)
        .build(Network::Testnet).unwrap();
    let (internal_descriptor, int_keymap, _) = Bip86(xprv, KeychainKind::Internal)
        .build(Network::Testnet).unwrap();
    println!("> external descriptor: {}", external_descriptor);
    println!("> internal descriptor: {}", internal_descriptor);
    println!("> tprv external descriptor: {}", external_descriptor.to_string_with_secret(&ext_keymap));
    println!("> tprv internal descriptor: {}", internal_descriptor.to_string_with_secret(&int_keymap));

    println!("> Generate a external address");
    for i in 0..5 {
        println!(">>>>>>>>>>>>>>>>>>>> external descriptor index: {}", i);
        let definite_desc = external_descriptor.at_derivation_index(i).unwrap();
        match definite_desc {
            Descriptor::Tr(ref tr) => {
                let path = tr.internal_key().full_derivation_path().unwrap();
                println!(">>> internal path: {}", path);
                let privkey = xprv.derive_priv(&secp, &path).unwrap();
                println!(">>> internal private key: {}", privkey.to_string());
                let pubkey = privkey.to_keypair(&secp).public_key();
                println!(">>> internal pubkey: {}", pubkey.to_string());
            },
            _ => {},
        }

        let private_key = xprv.derive_priv(&secp, &external_path.child(ChildNumber::from(i))).unwrap();
        let pubkey_from_pk = private_key.to_keypair(&secp).public_key();
        println!(">>> private key: {}", private_key.to_string());
        println!(">>> pubkey from private key: {}", pubkey_from_pk.to_string());
        println!(">>> descriptor: {}", definite_desc);
        let address = definite_desc.address(Network::Testnet).unwrap();
        println!(">>> address: {}", address);

        let derived_desc = definite_desc.derived_descriptor(&secp).unwrap();
        println!(">>> derived descriptor: {}", derived_desc);
        let derived_address = derived_desc.address(Network::Testnet).unwrap();
        println!(">>> derived address: {}", derived_address);
        match derived_desc {
            Descriptor::Tr(tr) => {
                let pubkey = tr.internal_key().to_public_key();
                println!(">>> internal pubkey: {}", pubkey.to_string());
                let xonly = tr.internal_key().to_x_only_pubkey();
                println!(">>> internal xonly: {}", xonly.to_string());
                let xonlypub = tr.internal_key().inner.x_only_public_key();
                println!(">>> internal xonlypub: {}, {}", xonlypub.0, xonlypub.1.to_u8());
            },
            _ => {},
        }
    }

    Ok(())
}
