//! Build script: compile `gwxds.proto` into Rust types via prost-build.

fn main() {
    let proto_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("proto");
    let proto_file = proto_dir.join("gwxds.proto");
    println!("cargo:rerun-if-changed={}", proto_file.display());
    prost_build::compile_protos(&[&proto_file], &[&proto_dir])
        .expect("prost_build failed: is protoc installed?");
}
