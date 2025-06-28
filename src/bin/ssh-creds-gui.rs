use anyhow::Result;
use keyring::Entry;
use std::io::{self, Write};

fn main() -> Result<()> {
    loop {
        clear_screen();
        show_menu();

        let choice = get_input("Select (1-5): ")?;

        match choice.trim() {
            "1" => store_in_secure_storage()?,
            "2" => create_temp_file()?,
            "3" => show_status()?,
            "4" => remove_password()?,
            "5" => {
                println!("Goodbye!");
                break;
            }
            _ => println!("Invalid choice"),
        }

        if choice.trim() != "5" {
            println!();
            print!("Press Enter to continue...");
            io::stdout().flush()?;
            let mut buffer = String::new();
            io::stdin().read_line(&mut buffer)?;
        }
    }

    Ok(())
}

fn clear_screen() {
    if cfg!(target_os = "windows") {
        let _ = std::process::Command::new("cmd")
            .args(&["/C", "cls"])
            .status();
    } else {
        print!("\x1B[2J\x1B[1;1H");
    }
}

fn show_menu() {
    println!("SSH MCP Encrypted Credentials Helper");
    println!("====================================");
    println!();
    println!("Choose an option:");

    if cfg!(target_os = "windows") {
        println!("1) Store master password in Windows Credential Manager (recommended)");
    } else if cfg!(target_os = "macos") {
        println!("1) Store master password in macOS Keychain (recommended)");
    } else {
        println!("1) Store master password in Secret Service (recommended)");
    }

    println!("2) Create temporary password file (less secure)");
    println!("3) Show current status");
    println!("4) Remove stored password");
    println!("5) Exit");
    println!();
}

fn get_input(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input)
}

fn get_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let password = rpassword::read_password()?;
    Ok(password)
}

fn store_in_secure_storage() -> Result<()> {
    println!();

    let storage_name = if cfg!(target_os = "windows") {
        "Windows Credential Manager"
    } else if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else {
        "Secret Service"
    };

    println!("This will store your master password in {}.", storage_name);
    println!("Claude Desktop will be able to access it automatically.");
    println!();

    let password = get_password("Enter master password: ")?;
    let password2 = get_password("Confirm master password: ")?;

    if password != password2 {
        println!("Passwords don't match!");
        return Ok(());
    }

    // Store using keyring crate
    let entry = Entry::new("ssh-mcp", "master-password")?;
    match entry.set_password(&password) {
        Ok(_) => {
            println!("✓ Master password stored in {} successfully!", storage_name);
            println!();
            println!("Claude Desktop will now be able to decrypt your credentials.");
        }
        Err(e) => {
            println!("Failed to store password: {}", e);

            // Platform-specific fallback instructions
            if cfg!(target_os = "windows") {
                println!();
                println!("Try running this command as Administrator:");
                println!(
                    "cmdkey /add:ssh-mcp /user:master-password /pass:{}",
                    password
                );
            } else if cfg!(target_os = "linux") {
                println!();
                println!("Make sure you have a Secret Service provider running (GNOME Keyring, KWallet, etc.)");
                println!("You can also try:");
                println!("secret-tool store --label='SSH MCP Master Password' service ssh-mcp username master-password");
            }
        }
    }

    Ok(())
}

fn create_temp_file() -> Result<()> {
    println!();
    println!("This will create a temporary file with your master password.");
    println!("The file will be deleted after first use.");
    println!("⚠️  This is less secure than using system credential storage!");
    println!();

    let password = get_password("Enter master password: ")?;

    let temp_file = std::env::temp_dir().join(format!("ssh-mcp-master-{}.tmp", std::process::id()));
    std::fs::write(&temp_file, password)?;

    // Set permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&temp_file, permissions)?;
    }

    println!("✓ Temporary password file created: {:?}", temp_file);
    println!();
    println!("This file will be automatically deleted after first use.");
    println!("Restart Claude Desktop to use encrypted credentials.");

    Ok(())
}

fn show_status() -> Result<()> {
    println!();
    println!("Current Status:");
    println!("===============");

    // Check secure storage
    let entry = Entry::new("ssh-mcp", "master-password")?;
    match entry.get_password() {
        Ok(_) => {
            let storage_name = if cfg!(target_os = "windows") {
                "Windows Credential Manager"
            } else if cfg!(target_os = "macos") {
                "macOS Keychain"
            } else {
                "Secret Service"
            };
            println!("✓ Master password is stored in {}", storage_name);
        }
        Err(_) => {
            println!("✗ No master password in system credential storage");
        }
    }

    // Check temp files
    let temp_pattern = std::env::temp_dir().join("ssh-mcp-master-*.tmp");
    let pattern_str = temp_pattern.to_string_lossy();
    if let Ok(paths) = glob::glob(&pattern_str) {
        let count = paths.count();
        if count > 0 {
            println!("⚠️  Found {} temporary password file(s)", count);
        }
    }

    // Check environment
    if std::env::var("SSH_MCP_MASTER_PASSWORD").is_ok() {
        println!("✓ SSH_MCP_MASTER_PASSWORD environment variable is set");
    }

    println!();

    // List credentials
    println!("Stored Credentials:");
    println!("-------------------");

    let ssh_creds_path = if cfg!(target_os = "windows") {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("ssh-creds.exe")))
            .unwrap_or_else(|| std::path::PathBuf::from("ssh-creds.exe"))
    } else {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("ssh-creds")))
            .unwrap_or_else(|| std::path::PathBuf::from("ssh-creds"))
    };

    match std::process::Command::new(&ssh_creds_path)
        .arg("list")
        .output()
    {
        Ok(output) => {
            print!("{}", String::from_utf8_lossy(&output.stdout));
            if !output.status.success() {
                print!("{}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(_) => println!("Unable to list credentials"),
    }

    Ok(())
}

fn remove_password() -> Result<()> {
    println!();
    println!("Remove stored master password");
    println!();

    // Remove from secure storage
    let entry = Entry::new("ssh-mcp", "master-password")?;
    match entry.delete_credential() {
        Ok(_) => println!("✓ Removed password from system credential storage"),
        Err(_) => println!("No password found in system credential storage"),
    }

    // Remove temp files
    let temp_pattern = std::env::temp_dir().join("ssh-mcp-master-*.tmp");
    let pattern_str = temp_pattern.to_string_lossy();
    if let Ok(paths) = glob::glob(&pattern_str) {
        let mut removed = 0;
        for path in paths {
            if let Ok(p) = path {
                if std::fs::remove_file(&p).is_ok() {
                    removed += 1;
                }
            }
        }
        if removed > 0 {
            println!("✓ Removed {} temporary password file(s)", removed);
        }
    }

    Ok(())
}
