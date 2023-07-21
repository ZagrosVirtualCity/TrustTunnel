use std::fs;
use toml_edit::{ArrayOfTables, Item, Key, Table};
use vpn_libs_endpoint::settings::{Http1Settings, Http2Settings, ListenProtocolSettings, QuicSettings, Settings};
use crate::Mode;
use crate::user_interaction::{ask_for_agreement, ask_for_input, ask_for_password, checked_overwrite, select_variant};

pub const DEFAULT_CREDENTIALS_PATH: &str = "credentials.toml";

pub struct Built {
    pub settings: Settings,
    pub credentials_path: String,
}

pub fn build() -> Built {
    let builder = Settings::builder()
        .listen_address(
            crate::get_predefined_params().listen_address.clone()
                .unwrap_or_else(|| ask_for_input(
                    Settings::doc_listen_address(),
                    Some(Settings::default_listen_address().to_string()),
                ))
        ).unwrap();

    Built {
        settings: builder
            .listen_protocols(ListenProtocolSettings {
                http1: Some(Http1Settings::builder().build()),
                http2: Some(Http2Settings::builder().build()),
                quic: Some(QuicSettings::builder().build()),
            })
            .build().expect("Couldn't build the library settings"),
        credentials_path: build_authenticator(),
    }
}

fn build_authenticator() -> String {
    if crate::get_mode() != Mode::NonInteractive
        && check_file_exists(".", DEFAULT_CREDENTIALS_PATH)
        && ask_for_agreement(&format!("Reuse the existing credentials file: {DEFAULT_CREDENTIALS_PATH}?"))
    {
        DEFAULT_CREDENTIALS_PATH.into()
    } else {
        let path = ask_for_input::<String>(
            "Path to the credentials file",
            Some(DEFAULT_CREDENTIALS_PATH.into()),
        );

        if checked_overwrite(&path, "Overwrite the existing credentials file?") {
            println!("Let's create user credentials");
            let users = build_user_list();
            fs::write(&path, compose_credentials_content(users.into_iter()))
                .expect("Couldn't write the credentials into a file");
            println!("The user credentials are written to file: {}", path);
        }

        path
    }
}

fn build_user_list() -> Vec<(String, String)> {
    if let Some(x) = crate::get_predefined_params().credentials.clone() {
        return vec![x];
    }

    let mut list = vec![(
        ask_for_input::<String>("Username", None),
        ask_for_password("Password"),
    )];

    loop {
        if "no" == select_variant("Add one more user?", &["yes", "no"], Some(1)) {
            break;
        }

        list.push((
            ask_for_input::<String>("Username", None),
            ask_for_password("Password"),
        ));
    }

    list
}

fn compose_credentials_content(clients: impl Iterator<Item=(String, String)>) -> String {
    let mut doc = toml_edit::Document::new();

    let x = clients
        .map(|(u, p)| Table::from_iter(
            std::iter::once(("username", u))
                .chain(std::iter::once(("password", p)))
        ))
        .collect::<ArrayOfTables>();

    doc.insert_formatted(&Key::new("client"), Item::ArrayOfTables(x));

    doc.to_string()
}

fn check_file_exists(path: &str, name: &str) -> bool {
    match fs::read_dir(path) {
        Ok(x) => x.filter_map(Result::ok)
            .filter(|entry| entry.metadata()
                .map(|meta| meta.is_file()).unwrap_or_default())
            .any(|entry| Ok(name) == entry.file_name().into_string().as_ref().map(String::as_str)),
        Err(_) => false,
    }
}
