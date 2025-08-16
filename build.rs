// build.rs

fn main() -> Result<(), Box<dyn std::error::Error>>  {
    let include_dirs = vec![
        "/home/loknop/chromium/src/out/cmplog_build/gen/",
        "/home/loknop/chromium/src/",
        "/home/loknop/chromium/src/third_party/dawn/"
    ];
    let targets = vec![
        "third_party/dawn/src/tint/utils/protos/ir_fuzz/ir_fuzz.proto",
    ];


    let out_dir = std::env::var("OUT_DIR").unwrap();

    // Add derives to all message types
    prost_build::Config::new()
    .message_attribute(
        ".", 
        "#[derive(serde::Serialize, serde::Deserialize, autarkie::Grammar)]"
    )
    .enum_attribute(
        ".",
        "#[derive(serde::Serialize, serde::Deserialize, autarkie::Grammar)]"
    )
    .include_file("mod.rs")
    .out_dir(&out_dir)
    .compile_protos(&targets, &include_dirs)?;
    Ok(())
}