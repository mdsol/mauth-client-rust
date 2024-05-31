use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=mauth-protocol-test-suite");

    let names: Vec<String> = fs::read_dir("mauth-protocol-test-suite/protocols/MWSV2/")
        .unwrap()
        .map(|r| {
            let r_path = r.unwrap().path();
            (
                r_path.clone(),
                r_path.file_name().unwrap().to_str().unwrap().to_string(),
            )
        })
        .filter(|(path, name)| path.join(format!("{}.sts", &name)).exists())
        .map(|(_, name)| name)
        .collect();

    let out_dir = env::var_os("OUT_DIR").unwrap();

    let mut code_str = String::new();
    for name in names {
        let formatted_name = name.replace('-', "_");
        code_str.push_str(&format!(
            r#"
#[tokio::test]
async fn {formatted_name}_generate_headers() {{
    test_generate_headers("{name}".to_string()).await;
}}
"#,
            formatted_name = &formatted_name,
            name = &name
        ));
    }
    fs::write(Path::new(&out_dir).join("protocol_tests.rs"), &code_str).unwrap();
}
