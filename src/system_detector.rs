use serde::{Deserialize, Serialize};
use ssh2::Session;
use std::collections::HashMap;
use std::io::Read;

use crate::error::SSHError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os_type: OsType,
    pub os_version: String,
    pub architecture: String,
    pub hostname: String,
    pub kernel_version: String,
    pub shell: ShellType,
    pub has_sudo: bool,
    pub package_manager: Option<PackageManager>,
    pub init_system: Option<InitSystem>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OsType {
    Linux(LinuxDistro),
    MacOS,
    Windows,
    BSD(BSDVariant),
    Solaris,
    AIX,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LinuxDistro {
    Ubuntu,
    Debian,
    RedHat,
    CentOS,
    Fedora,
    SUSE,
    Arch,
    Alpine,
    Amazon,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BSDVariant {
    FreeBSD,
    OpenBSD,
    NetBSD,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ShellType {
    Bash,
    Zsh,
    Sh,
    Csh,
    Tcsh,
    Fish,
    PowerShell,
    Cmd,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PackageManager {
    Apt,
    Yum,
    Dnf,
    Zypper,
    Pacman,
    Apk,
    Brew,
    Pkg,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InitSystem {
    Systemd,
    SysVInit,
    Upstart,
    OpenRC,
    Runit,
    Unknown(String),
}

pub struct SystemDetector;

impl SystemDetector {
    pub fn detect(session: &Session) -> Result<SystemInfo, SSHError> {
        // Get basic system info
        let uname_output = Self::execute_command(session, "uname -a")?;
        let os_type = Self::detect_os_type(session)?;
        let shell = Self::detect_shell(session)?;
        let has_sudo = Self::check_sudo(session)?;
        let hostname = Self::get_hostname(session)?;
        let architecture = Self::get_architecture(session)?;
        let kernel_version = Self::get_kernel_version(&uname_output);
        let package_manager = Self::detect_package_manager(session, &os_type)?;
        let init_system = Self::detect_init_system(session, &os_type)?;
        let os_version = Self::get_os_version(session, &os_type)?;

        Ok(SystemInfo {
            os_type,
            os_version,
            architecture,
            hostname,
            kernel_version,
            shell,
            has_sudo,
            package_manager,
            init_system,
        })
    }

    fn execute_command(session: &Session, command: &str) -> Result<String, SSHError> {
        let mut channel = session
            .channel_session()
            .map_err(|e| SSHError::Connection(format!("Failed to create channel: {}", e)))?;

        channel
            .exec(command)
            .map_err(|e| SSHError::Connection(format!("Failed to execute command: {}", e)))?;

        let mut output = String::new();
        channel
            .read_to_string(&mut output)
            .map_err(|e| SSHError::Connection(format!("Failed to read output: {}", e)))?;

        channel
            .wait_close()
            .map_err(|e| SSHError::Connection(format!("Failed to close channel: {}", e)))?;

        let exit_status = channel
            .exit_status()
            .map_err(|e| SSHError::Connection(format!("Failed to get exit status: {}", e)))?;

        if exit_status != 0 {
            return Ok(String::new());
        }

        Ok(output.trim().to_string())
    }

    fn detect_os_type(session: &Session) -> Result<OsType, SSHError> {
        // Check for Linux
        if let Ok(os_release) = Self::execute_command(session, "cat /etc/os-release 2>/dev/null") {
            if !os_release.is_empty() {
                return Ok(Self::parse_linux_distro(&os_release));
            }
        }

        // Check for macOS
        if let Ok(sw_vers) = Self::execute_command(session, "sw_vers 2>/dev/null") {
            if sw_vers.contains("macOS") || sw_vers.contains("Mac OS X") {
                return Ok(OsType::MacOS);
            }
        }

        // Check for BSD variants
        if let Ok(uname) = Self::execute_command(session, "uname -s") {
            if uname.contains("FreeBSD") {
                return Ok(OsType::BSD(BSDVariant::FreeBSD));
            } else if uname.contains("OpenBSD") {
                return Ok(OsType::BSD(BSDVariant::OpenBSD));
            } else if uname.contains("NetBSD") {
                return Ok(OsType::BSD(BSDVariant::NetBSD));
            } else if uname.contains("SunOS") {
                return Ok(OsType::Solaris);
            } else if uname.contains("AIX") {
                return Ok(OsType::AIX);
            }
        }

        // Check for Windows
        if let Ok(systeminfo) = Self::execute_command(
            session,
            "systeminfo 2>/dev/null | findstr /B /C:\"OS Name\"",
        ) {
            if systeminfo.contains("Windows") {
                return Ok(OsType::Windows);
            }
        }

        Ok(OsType::Unknown)
    }

    fn parse_linux_distro(os_release: &str) -> OsType {
        let os_release_lower = os_release.to_lowercase();

        if os_release_lower.contains("ubuntu") {
            OsType::Linux(LinuxDistro::Ubuntu)
        } else if os_release_lower.contains("debian") {
            OsType::Linux(LinuxDistro::Debian)
        } else if os_release_lower.contains("red hat") || os_release_lower.contains("rhel") {
            OsType::Linux(LinuxDistro::RedHat)
        } else if os_release_lower.contains("centos") {
            OsType::Linux(LinuxDistro::CentOS)
        } else if os_release_lower.contains("fedora") {
            OsType::Linux(LinuxDistro::Fedora)
        } else if os_release_lower.contains("suse") {
            OsType::Linux(LinuxDistro::SUSE)
        } else if os_release_lower.contains("arch") {
            OsType::Linux(LinuxDistro::Arch)
        } else if os_release_lower.contains("alpine") {
            OsType::Linux(LinuxDistro::Alpine)
        } else if os_release_lower.contains("amazon") {
            OsType::Linux(LinuxDistro::Amazon)
        } else {
            // Try to extract the ID field
            if let Some(id_line) = os_release.lines().find(|l| l.starts_with("ID=")) {
                let id = id_line.trim_start_matches("ID=").trim_matches('"');
                OsType::Linux(LinuxDistro::Other(id.to_string()))
            } else {
                OsType::Linux(LinuxDistro::Other("Unknown".to_string()))
            }
        }
    }

    fn detect_shell(session: &Session) -> Result<ShellType, SSHError> {
        if let Ok(shell_path) = Self::execute_command(session, "echo $SHELL") {
            match shell_path.split('/').last() {
                Some("bash") => Ok(ShellType::Bash),
                Some("zsh") => Ok(ShellType::Zsh),
                Some("sh") => Ok(ShellType::Sh),
                Some("csh") => Ok(ShellType::Csh),
                Some("tcsh") => Ok(ShellType::Tcsh),
                Some("fish") => Ok(ShellType::Fish),
                Some("pwsh") | Some("powershell") => Ok(ShellType::PowerShell),
                Some(other) => Ok(ShellType::Unknown(other.to_string())),
                None => Ok(ShellType::Unknown("unknown".to_string())),
            }
        } else {
            Ok(ShellType::Unknown("unknown".to_string()))
        }
    }

    fn check_sudo(session: &Session) -> Result<bool, SSHError> {
        let result = Self::execute_command(session, "sudo -n true 2>/dev/null && echo 'has_sudo'")?;
        Ok(result.contains("has_sudo"))
    }

    fn get_hostname(session: &Session) -> Result<String, SSHError> {
        Self::execute_command(session, "hostname")
    }

    fn get_architecture(session: &Session) -> Result<String, SSHError> {
        Self::execute_command(session, "uname -m")
    }

    fn get_kernel_version(uname_output: &str) -> String {
        uname_output
            .split_whitespace()
            .nth(2)
            .unwrap_or("unknown")
            .to_string()
    }

    fn detect_package_manager(
        session: &Session,
        os_type: &OsType,
    ) -> Result<Option<PackageManager>, SSHError> {
        match os_type {
            OsType::Linux(_) => {
                // Check for common package managers
                if Self::execute_command(session, "which apt-get 2>/dev/null")?.is_empty() == false
                {
                    Ok(Some(PackageManager::Apt))
                } else if Self::execute_command(session, "which yum 2>/dev/null")?.is_empty()
                    == false
                {
                    Ok(Some(PackageManager::Yum))
                } else if Self::execute_command(session, "which dnf 2>/dev/null")?.is_empty()
                    == false
                {
                    Ok(Some(PackageManager::Dnf))
                } else if Self::execute_command(session, "which zypper 2>/dev/null")?.is_empty()
                    == false
                {
                    Ok(Some(PackageManager::Zypper))
                } else if Self::execute_command(session, "which pacman 2>/dev/null")?.is_empty()
                    == false
                {
                    Ok(Some(PackageManager::Pacman))
                } else if Self::execute_command(session, "which apk 2>/dev/null")?.is_empty()
                    == false
                {
                    Ok(Some(PackageManager::Apk))
                } else {
                    Ok(None)
                }
            }
            OsType::MacOS => {
                if Self::execute_command(session, "which brew 2>/dev/null")?.is_empty() == false {
                    Ok(Some(PackageManager::Brew))
                } else {
                    Ok(None)
                }
            }
            OsType::BSD(_) => {
                if Self::execute_command(session, "which pkg 2>/dev/null")?.is_empty() == false {
                    Ok(Some(PackageManager::Pkg))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    fn detect_init_system(
        session: &Session,
        os_type: &OsType,
    ) -> Result<Option<InitSystem>, SSHError> {
        match os_type {
            OsType::Linux(_) => {
                // Check for systemd
                if Self::execute_command(session, "pidof systemd 2>/dev/null")?.is_empty() == false
                {
                    Ok(Some(InitSystem::Systemd))
                } else if Self::execute_command(session, "[ -d /etc/init.d ] && echo 'sysvinit'")?
                    .contains("sysvinit")
                {
                    Ok(Some(InitSystem::SysVInit))
                } else if Self::execute_command(session, "which initctl 2>/dev/null")?.is_empty()
                    == false
                {
                    Ok(Some(InitSystem::Upstart))
                } else if Self::execute_command(session, "[ -d /etc/openrc ] && echo 'openrc'")?
                    .contains("openrc")
                {
                    Ok(Some(InitSystem::OpenRC))
                } else if Self::execute_command(session, "which runit 2>/dev/null")?.is_empty()
                    == false
                {
                    Ok(Some(InitSystem::Runit))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    fn get_os_version(session: &Session, os_type: &OsType) -> Result<String, SSHError> {
        match os_type {
            OsType::Linux(_) => {
                if let Ok(version) = Self::execute_command(
                    session,
                    "cat /etc/os-release | grep VERSION_ID | cut -d= -f2 | tr -d '\"'",
                ) {
                    if !version.is_empty() {
                        return Ok(version);
                    }
                }
                Ok("Unknown".to_string())
            }
            OsType::MacOS => {
                if let Ok(version) = Self::execute_command(session, "sw_vers -productVersion") {
                    Ok(version)
                } else {
                    Ok("Unknown".to_string())
                }
            }
            _ => Ok("Unknown".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_linux_distro() {
        let ubuntu_release = r#"
NAME="Ubuntu"
VERSION="20.04.3 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
"#;
        match SystemDetector::parse_linux_distro(ubuntu_release) {
            OsType::Linux(LinuxDistro::Ubuntu) => {}
            _ => panic!("Failed to detect Ubuntu"),
        }

        let centos_release = r#"
NAME="CentOS Linux"
VERSION="7 (Core)"
ID="centos"
"#;
        match SystemDetector::parse_linux_distro(centos_release) {
            OsType::Linux(LinuxDistro::CentOS) => {}
            _ => panic!("Failed to detect CentOS"),
        }
    }
}
