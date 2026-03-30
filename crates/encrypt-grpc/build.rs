fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_file = manifest_dir.join("../../proto/encrypt_service.proto");
    let proto_dir = proto_file.parent().unwrap().to_path_buf();

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_with_config(
            prost_build::Config::new(),
            &[&proto_file],
            &[&proto_dir],
        )?;
    Ok(())
}
