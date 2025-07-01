use crate::system_detector::{InitSystem, OsType, PackageManager, SystemInfo};
use std::collections::HashMap;

pub struct CommandValidator {
    system_info: SystemInfo,
    command_aliases: HashMap<String, Vec<String>>,
    dangerous_commands: Vec<String>,
}

impl CommandValidator {
    pub fn new(system_info: SystemInfo) -> Self {
        let mut validator = Self {
            system_info,
            command_aliases: HashMap::new(),
            dangerous_commands: Vec::new(),
        };
        validator.initialize_aliases();
        validator.initialize_dangerous_commands();
        validator
    }

    fn initialize_aliases(&mut self) {
        // Common command aliases across systems
        self.command_aliases
            .insert("ls".to_string(), vec!["dir".to_string()]);
        self.command_aliases
            .insert("cat".to_string(), vec!["type".to_string()]);
        self.command_aliases
            .insert("clear".to_string(), vec!["cls".to_string()]);

        // Package manager aliases
        match &self.system_info.package_manager {
            Some(PackageManager::Apt) => {
                self.command_aliases.insert(
                    "install".to_string(),
                    vec!["apt install".to_string(), "apt-get install".to_string()],
                );
                self.command_aliases.insert(
                    "update".to_string(),
                    vec!["apt update".to_string(), "apt-get update".to_string()],
                );
                self.command_aliases.insert(
                    "search".to_string(),
                    vec!["apt search".to_string(), "apt-cache search".to_string()],
                );
            }
            Some(PackageManager::Yum) => {
                self.command_aliases
                    .insert("install".to_string(), vec!["yum install".to_string()]);
                self.command_aliases
                    .insert("update".to_string(), vec!["yum update".to_string()]);
                self.command_aliases
                    .insert("search".to_string(), vec!["yum search".to_string()]);
            }
            Some(PackageManager::Brew) => {
                self.command_aliases
                    .insert("install".to_string(), vec!["brew install".to_string()]);
                self.command_aliases
                    .insert("update".to_string(), vec!["brew update".to_string()]);
                self.command_aliases
                    .insert("search".to_string(), vec!["brew search".to_string()]);
            }
            _ => {}
        }

        // Service management aliases
        match &self.system_info.init_system {
            Some(InitSystem::Systemd) => {
                self.command_aliases.insert(
                    "service start".to_string(),
                    vec!["systemctl start".to_string()],
                );
                self.command_aliases.insert(
                    "service stop".to_string(),
                    vec!["systemctl stop".to_string()],
                );
                self.command_aliases.insert(
                    "service restart".to_string(),
                    vec!["systemctl restart".to_string()],
                );
                self.command_aliases.insert(
                    "service status".to_string(),
                    vec!["systemctl status".to_string()],
                );
            }
            Some(InitSystem::SysVInit) => {
                self.command_aliases
                    .insert("systemctl start".to_string(), vec!["service".to_string()]);
                self.command_aliases
                    .insert("systemctl stop".to_string(), vec!["service".to_string()]);
            }
            _ => {}
        }
    }

    fn initialize_dangerous_commands(&mut self) {
        self.dangerous_commands = vec![
            "rm -rf /".to_string(),
            "rm -rf /*".to_string(),
            "mkfs".to_string(),
            "dd if=/dev/zero".to_string(),
            "dd if=/dev/random".to_string(),
            "> /dev/sda".to_string(),
            "chmod -R 777 /".to_string(),
            "chmod -R 000 /".to_string(),
            ":(){ :|:& };:".to_string(), // Fork bomb
            "mv ~ /dev/null".to_string(),
            "wget -O - | sh".to_string(),
            "curl -s | bash".to_string(),
        ];
    }

    pub fn validate_command(&self, command: &str) -> CommandValidation {
        let trimmed = command.trim();

        // Check for dangerous commands
        if self.is_dangerous_command(trimmed) {
            return CommandValidation::Dangerous(trimmed.to_string());
        }

        // Check for system-specific corrections
        if let Some(corrected) = self.correct_command(trimmed) {
            return CommandValidation::Corrected(corrected);
        }

        // Check for command availability
        if let Some(alternative) = self.suggest_alternative(trimmed) {
            return CommandValidation::Alternative(alternative);
        }

        CommandValidation::Valid
    }

    fn is_dangerous_command(&self, command: &str) -> bool {
        let command_lower = command.to_lowercase();
        self.dangerous_commands
            .iter()
            .any(|dangerous| command_lower.contains(&dangerous.to_lowercase()))
    }

    fn correct_command(&self, command: &str) -> Option<String> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }

        // Correct Windows-style commands on Unix systems
        match (&self.system_info.os_type, parts[0]) {
            (OsType::Linux(_) | OsType::MacOS | OsType::BSD(_), "dir") => {
                let mut corrected = vec!["ls"];
                corrected.extend(&parts[1..]);
                Some(corrected.join(" "))
            }
            (OsType::Linux(_) | OsType::MacOS | OsType::BSD(_), "cls") => Some("clear".to_string()),
            (OsType::Linux(_) | OsType::MacOS | OsType::BSD(_), "type") if parts.len() > 1 => {
                let mut corrected = vec!["cat"];
                corrected.extend(&parts[1..]);
                Some(corrected.join(" "))
            }
            (OsType::Linux(_) | OsType::MacOS | OsType::BSD(_), "copy") if parts.len() > 2 => {
                let mut corrected = vec!["cp"];
                corrected.extend(&parts[1..]);
                Some(corrected.join(" "))
            }
            (OsType::Linux(_) | OsType::MacOS | OsType::BSD(_), "move") if parts.len() > 2 => {
                let mut corrected = vec!["mv"];
                corrected.extend(&parts[1..]);
                Some(corrected.join(" "))
            }
            (OsType::Linux(_) | OsType::MacOS | OsType::BSD(_), "del") if parts.len() > 1 => {
                let mut corrected = vec!["rm"];
                corrected.extend(&parts[1..]);
                Some(corrected.join(" "))
            }
            _ => None,
        }
    }

    fn suggest_alternative(&self, command: &str) -> Option<String> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }

        // Suggest package manager commands
        match parts[0] {
            "apt" | "apt-get"
                if !matches!(&self.system_info.package_manager, Some(PackageManager::Apt)) =>
            {
                self.get_package_manager_command(&parts)
            }
            "yum" if !matches!(&self.system_info.package_manager, Some(PackageManager::Yum)) => {
                self.get_package_manager_command(&parts)
            }
            "brew"
                if !matches!(
                    &self.system_info.package_manager,
                    Some(PackageManager::Brew)
                ) =>
            {
                self.get_package_manager_command(&parts)
            }
            _ => None,
        }
    }

    fn get_package_manager_command(&self, parts: &[&str]) -> Option<String> {
        if parts.len() < 2 {
            return None;
        }

        let action = parts[1];
        let args = if parts.len() > 2 { &parts[2..] } else { &[] };

        match (&self.system_info.package_manager, action) {
            (Some(PackageManager::Apt), _) => Some(format!("apt {} {}", action, args.join(" "))),
            (Some(PackageManager::Yum), _) => Some(format!("yum {} {}", action, args.join(" "))),
            (Some(PackageManager::Dnf), _) => Some(format!("dnf {} {}", action, args.join(" "))),
            (Some(PackageManager::Brew), _) => Some(format!("brew {} {}", action, args.join(" "))),
            _ => None,
        }
    }

    pub fn get_safe_command(&self, command: &str) -> String {
        match self.validate_command(command) {
            CommandValidation::Valid => command.to_string(),
            CommandValidation::Corrected(corrected) => corrected,
            CommandValidation::Alternative(alternative) => alternative,
            CommandValidation::Dangerous(_) => {
                // Return a safe echo command that explains why the command was blocked
                format!("echo 'Command blocked for safety reasons: {}'", command)
            }
        }
    }

    pub fn requires_sudo(&self, command: &str) -> bool {
        let sudo_required_commands = vec![
            "apt",
            "apt-get",
            "yum",
            "dnf",
            "zypper",
            "pacman",
            "systemctl",
            "service",
            "mount",
            "umount",
            "useradd",
            "userdel",
            "usermod",
            "groupadd",
            "iptables",
            "firewall-cmd",
            "ufw",
        ];

        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return false;
        }

        // Already has sudo
        if parts[0] == "sudo" {
            return false;
        }

        // Check if command requires sudo
        sudo_required_commands.contains(&parts[0])
    }

    pub fn add_sudo_if_needed(&self, command: &str) -> String {
        if self.system_info.has_sudo && self.requires_sudo(command) {
            format!("sudo {}", command)
        } else {
            command.to_string()
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum CommandValidation {
    Valid,
    Corrected(String),
    Alternative(String),
    Dangerous(String),
}

pub struct CommandHistory {
    history: Vec<CommandHistoryEntry>,
    max_size: usize,
}

#[derive(Debug, Clone)]
pub struct CommandHistoryEntry {
    pub command: String,
    pub corrected_command: Option<String>,
    pub exit_code: Option<i32>,
    pub timestamp: std::time::SystemTime,
}

impl CommandHistory {
    pub fn new(max_size: usize) -> Self {
        Self {
            history: Vec::new(),
            max_size,
        }
    }

    pub fn add(
        &mut self,
        command: String,
        corrected_command: Option<String>,
        exit_code: Option<i32>,
    ) {
        let entry = CommandHistoryEntry {
            command,
            corrected_command,
            exit_code,
            timestamp: std::time::SystemTime::now(),
        };

        self.history.push(entry);

        if self.history.len() > self.max_size {
            self.history.remove(0);
        }
    }

    pub fn get_last_successful(&self) -> Option<&CommandHistoryEntry> {
        self.history
            .iter()
            .rev()
            .find(|entry| entry.exit_code == Some(0))
    }

    pub fn get_frequently_failed(&self) -> Vec<&str> {
        let mut failed_counts: HashMap<&str, usize> = HashMap::new();

        for entry in &self.history {
            if entry.exit_code != Some(0) {
                *failed_counts.entry(&entry.command).or_insert(0) += 1;
            }
        }

        let mut failed_commands: Vec<(&str, usize)> = failed_counts.into_iter().collect();
        failed_commands.sort_by(|a, b| b.1.cmp(&a.1));

        failed_commands
            .into_iter()
            .take(5)
            .map(|(cmd, _)| cmd)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_detector::*;

    fn create_test_system_info() -> SystemInfo {
        SystemInfo {
            os_type: OsType::Linux(LinuxDistro::Ubuntu),
            os_version: "20.04".to_string(),
            architecture: "x86_64".to_string(),
            hostname: "test-host".to_string(),
            kernel_version: "5.4.0".to_string(),
            shell: ShellType::Bash,
            has_sudo: true,
            package_manager: Some(PackageManager::Apt),
            init_system: Some(InitSystem::Systemd),
        }
    }

    #[test]
    fn test_dangerous_command_detection() {
        let system_info = create_test_system_info();
        let validator = CommandValidator::new(system_info);

        assert_eq!(
            validator.validate_command("rm -rf /"),
            CommandValidation::Dangerous("rm -rf /".to_string())
        );

        assert_eq!(
            validator.validate_command("ls -la"),
            CommandValidation::Valid
        );
    }

    #[test]
    fn test_command_correction() {
        let system_info = create_test_system_info();
        let validator = CommandValidator::new(system_info);

        assert_eq!(
            validator.validate_command("dir"),
            CommandValidation::Corrected("ls".to_string())
        );

        assert_eq!(
            validator.validate_command("cls"),
            CommandValidation::Corrected("clear".to_string())
        );
    }

    #[test]
    fn test_sudo_detection() {
        let system_info = create_test_system_info();
        let validator = CommandValidator::new(system_info);

        assert!(validator.requires_sudo("apt install vim"));
        assert!(!validator.requires_sudo("sudo apt install vim"));
        assert!(!validator.requires_sudo("ls -la"));
    }
}
