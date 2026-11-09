use std::{fs, process::Command};

#[test]
fn separate_stages_private_source_key_reuse_and_tampering() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("cli-private-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let run = |args: &[&str], expected: bool| {
        let output = Command::new(env!("CARGO_BIN_EXE_valis-nova-demo"))
            .current_dir(&dir)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            expected,
            "args={args:?}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    fs::write(dir.join("old.txt"), "aSECRETb").unwrap();
    fs::write(dir.join("new.txt"), "ab").unwrap();
    run(&["diff", "old.txt", "new.txt", "public.json"], true);
    let public_bytes = fs::read(dir.join("public.json")).unwrap();
    let public: serde_json::Value = serde_json::from_slice(&public_bytes).unwrap();
    assert_eq!(public["before_len"], 8);
    assert!(public.get("version").is_none());
    assert_eq!(public["after"], serde_json::json!([97, 98]));
    assert!(public.get("before").is_none());
    assert!(!String::from_utf8_lossy(&public_bytes).contains("SECRET"));

    // setup 无法访问原文，因为原文件此时不存在。
    fs::remove_file(dir.join("old.txt")).unwrap();
    run(&["setup", "public.json", "pk.bin", "vk.bin"], true);
    let pk_before = fs::read(dir.join("pk.bin")).unwrap();
    let vk_before = fs::read(dir.join("vk.bin")).unwrap();
    fs::write(dir.join("private.txt"), "aSECRETb").unwrap();
    run(
        &["prove", "private.txt", "public.json", "pk.bin", "proof.bin"],
        true,
    );
    fs::remove_file(dir.join("private.txt")).unwrap();
    // 独立验证进程只持有公开语句、vk 和压缩证明。
    run(&["verify", "public.json", "vk.bin", "proof.bin"], true);

    fs::write(dir.join("bad.txt"), "xSECRETb").unwrap();
    run(
        &["prove", "bad.txt", "public.json", "pk.bin", "bad-proof.bin"],
        false,
    );

    let mut changed = public.clone();
    changed["after"] = serde_json::json!([97, 99]);
    fs::write(
        dir.join("changed.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    run(&["verify", "changed.json", "vk.bin", "proof.bin"], false);
    changed = public.clone();
    changed["edits"] = serde_json::json!([{"Delete":6},{"Keep":1},{"Keep":1}]);
    fs::write(
        dir.join("changed.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    run(&["verify", "changed.json", "vk.bin", "proof.bin"], false);

    // 相同形状、不同新文和操作类型，仍复用原 pk/vk，不调用 setup。
    changed = public.clone();
    changed["after"] = serde_json::json!([97, 99]);
    changed["edits"] = serde_json::json!([{"Keep":1},{"Delete":7},{"Insert":[99]}]);
    fs::write(
        dir.join("second.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    fs::write(dir.join("private.txt"), "aHIDDENb").unwrap();
    run(
        &[
            "prove",
            "private.txt",
            "second.json",
            "pk.bin",
            "second.bin",
        ],
        true,
    );
    fs::remove_file(dir.join("private.txt")).unwrap();
    run(&["verify", "second.json", "vk.bin", "second.bin"], true);
    assert_eq!(pk_before, fs::read(dir.join("pk.bin")).unwrap());
    assert_eq!(vk_before, fs::read(dir.join("vk.bin")).unwrap());

    // 错误 insert 不在 Statement 被拦截：使用同形状参数进入电路后仍被拒绝。
    let mut wrong_insert = changed.clone();
    wrong_insert["edits"] = serde_json::json!([{"Keep":1},{"Delete":7},{"Insert":[100]}]);
    fs::write(
        dir.join("wrong-insert.json"),
        serde_json::to_vec(&wrong_insert).unwrap(),
    )
    .unwrap();
    fs::write(dir.join("private.txt"), "aHIDDENb").unwrap();
    let failed = run(
        &[
            "prove",
            "private.txt",
            "wrong-insert.json",
            "pk.bin",
            "rejected.bin",
        ],
        false,
    );
    assert!(!String::from_utf8_lossy(&failed.stderr).contains("insert payload does not match"));

    // 不同长度/块数不能静默复用参数。
    changed["before_len"] = 9.into();
    changed["edits"] = serde_json::json!([{"Keep":1},{"Delete":8},{"Insert":[99]}]);
    fs::write(
        dir.join("different-shape.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    fs::write(dir.join("private.txt"), "aHIDDENbb").unwrap();
    run(
        &[
            "prove",
            "private.txt",
            "different-shape.json",
            "pk.bin",
            "wrong.bin",
        ],
        false,
    );
    // 拒绝尾随数据和错误用途的产物。
    let mut corrupt = fs::read(dir.join("proof.bin")).unwrap();
    corrupt.push(0);
    fs::write(dir.join("corrupt.bin"), corrupt).unwrap();
    run(&["verify", "public.json", "vk.bin", "corrupt.bin"], false);
    run(&["verify", "public.json", "vk.bin", "vk.bin"], false);
    run(&["diff", "bad.txt", "new.txt", "bad.txt"], false);
    assert_eq!(fs::read_to_string(dir.join("bad.txt")).unwrap(), "xSECRETb");

    // 非 UTF-8 的原文和目标也可复用相同形状参数（8 字节、2 字节、3 块）。
    fs::write(dir.join("binary-old.bin"), [255, 1, 2, 3, 4, 5, 6, 128]).unwrap();
    fs::write(dir.join("binary-new.bin"), [255, 128]).unwrap();
    run(
        &["diff", "binary-old.bin", "binary-new.bin", "binary.json"],
        true,
    );
    let binary: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("binary.json")).unwrap()).unwrap();
    assert_eq!(binary["after"], serde_json::json!([255, 128]));
    run(
        &[
            "prove",
            "binary-old.bin",
            "binary.json",
            "pk.bin",
            "binary-proof.bin",
        ],
        true,
    );
    fs::remove_file(dir.join("binary-old.bin")).unwrap();
    run(
        &["verify", "binary.json", "vk.bin", "binary-proof.bin"],
        true,
    );
    // 旧版参数格式仍明确拒绝，不能静默复用。
    let mut old_key = vk_before.clone();
    old_key.splice(
        ..b"VALIS-NOVA-PRIVATE-BYTES-V2\0".len(),
        b"VALIS-NOVA-PRIVATE-V1\0".iter().copied(),
    );
    fs::write(dir.join("legacy-vk.bin"), old_key).unwrap();
    run(
        &["verify", "public.json", "legacy-vk.bin", "proof.bin"],
        false,
    );
}
