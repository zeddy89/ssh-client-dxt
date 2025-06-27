use crate::config::{PortForwardConfig, SshConfig};
use crate::error::{Result, SshMcpError};
use chrono::{DateTime, Utc};
// Remove ssh2 imports as Session is not Send and can't be stored in async context
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{info, warn};
use uuid::Uuid;

pub struct SshSession {
    pub id: String,
    pub config: SshConfig,
    // Session removed - ssh2::Session is not Send
    // We'll create new connections as needed in blocking tasks
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub port_forwards: Vec<PortForwardConfig>,
}

impl SshSession {
    pub fn new(config: SshConfig) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            config,
            created_at: now,
            last_activity: now,
            port_forwards: Vec::new(),
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }

    pub fn is_expired(&self, timeout: Duration) -> bool {
        let elapsed = Utc::now().signed_duration_since(self.last_activity);
        elapsed.num_seconds() > timeout.as_secs() as i64
    }

    pub fn sftp(&self) -> Result<Sftp> {
        self.session
            .sftp()
            .map_err(|e| SshMcpError::FileOperation(e.to_string()))
    }
}

pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<String, SshSession>>>,
    max_sessions: usize,
    session_timeout: Duration,
}

impl SessionManager {
    pub fn new(max_sessions: usize, session_timeout: Duration) -> Self {
        let manager = Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            max_sessions,
            session_timeout,
        };

        // Start cleanup task
        let sessions = manager.sessions.clone();
        let timeout = session_timeout;
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(60)).await;
                Self::cleanup_expired_sessions(sessions.clone(), timeout).await;
            }
        });

        manager
    }

    pub async fn add_session(&self, session: SshSession) -> Result<String> {
        let mut sessions = self.sessions.lock().await;

        if sessions.len() >= self.max_sessions {
            return Err(SshMcpError::MaxSessionsReached(self.max_sessions));
        }

        let session_id = session.id.clone();
        info!(
            "Adding SSH session: {} to {}@{}:{}",
            session_id, session.config.username, session.config.host, session.config.port
        );

        sessions.insert(session_id.clone(), session);
        Ok(session_id)
    }

    pub async fn get_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().await;

        if let Some(session) = sessions.get_mut(session_id) {
            session.update_activity();
            Ok(())
        } else {
            Err(SshMcpError::SessionNotFound(session_id.to_string()))
        }
    }

    pub async fn with_session<F, R>(&self, session_id: &str, f: F) -> Result<R>
    where
        F: FnOnce(&mut SshSession) -> Result<R>,
    {
        let mut sessions = self.sessions.lock().await;

        if let Some(session) = sessions.get_mut(session_id) {
            session.update_activity();
            f(session)
        } else {
            Err(SshMcpError::SessionNotFound(session_id.to_string()))
        }
    }

    pub async fn remove_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().await;

        if sessions.remove(session_id).is_some() {
            info!("Removed SSH session: {}", session_id);
            Ok(())
        } else {
            Err(SshMcpError::SessionNotFound(session_id.to_string()))
        }
    }

    pub async fn list_sessions(&self) -> Vec<(String, SshConfig, DateTime<Utc>)> {
        let sessions = self.sessions.lock().await;
        sessions
            .iter()
            .map(|(id, session)| (id.clone(), session.config.clone(), session.created_at))
            .collect()
    }

    async fn cleanup_expired_sessions(
        sessions: Arc<Mutex<HashMap<String, SshSession>>>,
        timeout: Duration,
    ) {
        let mut sessions = sessions.lock().await;
        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| session.is_expired(timeout))
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired {
            if let Some(session) = sessions.remove(&id) {
                warn!(
                    "Cleaning up expired session: {} to {}@{}",
                    id, session.config.username, session.config.host
                );
            }
        }
    }

    pub async fn clear_all_sessions(&self) {
        let mut sessions = self.sessions.lock().await;
        let count = sessions.len();
        sessions.clear();
        info!("Cleared all {} SSH sessions", count);
    }
}
