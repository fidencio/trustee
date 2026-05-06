use std::time::Duration;

use mobc::{Manager, Pool};
use serde::Deserialize;
use serde_json::Value;
use tonic::transport::Channel;
use tracing::{debug, info, warn};

use self::rvps_api::{
    reference_value_provider_service_client::ReferenceValueProviderServiceClient,
    ReferenceValueQueryRequest, ReferenceValueRegisterRequest,
};

use super::{Result, RvpsApi};

pub mod rvps_api {
    tonic::include_proto!("reference");
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct RvpsRemoteConfig {
    /// Address of remote RVPS. If this field is given, a remote RVPS will be connected to.
    /// If this field is not given, a built-in RVPS will be used.
    #[serde(default = "default_address")]
    pub address: String,
}

fn default_address() -> String {
    "127.0.0.1:50003".into()
}

/// The default pool size for the RVPS client.
const DEFAULT_RVPS_POOL_SIZE: u64 = 10;

pub struct Agent {
    pool: Pool<GrpcManager>,
}

impl Agent {
    pub async fn new(addr: &str) -> Result<Self> {
        info!(
            "connect to remote RVPS [{}] with pool size {}",
            addr, DEFAULT_RVPS_POOL_SIZE
        );

        let mut address = addr.to_string();
        if !address.starts_with("http://") && !address.starts_with("https://") {
            debug!("add http:// prefix to the rvps grpc address [{}]", address);
            address = format!("http://{}", address);
        }

        let manager = GrpcManager { address };
        let pool = Pool::builder()
            .max_open(DEFAULT_RVPS_POOL_SIZE)
            .max_idle_lifetime(Some(Duration::from_secs(30)))
            .build(manager);

        // the mobc Pool builder does not establish an actual connection,
        // so we need to test the connection and validate the parameters at launch time
        let _client = pool.get().await?;
        Ok(Self { pool })
    }
}
#[async_trait::async_trait]
impl RvpsApi for Agent {
    async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        let req = tonic::Request::new(ReferenceValueRegisterRequest {
            message: message.to_string(),
        });
        let mut client = self.pool.get().await?;
        let _ = client.register_reference_value(req).await?;
        Ok(())
    }

    async fn query_reference_value(&self, reference_value_id: &str) -> Result<Option<Value>> {
        let req = tonic::Request::new(ReferenceValueQueryRequest {
            reference_value_id: reference_value_id.to_string(),
        });
        let mut client = self.pool.get().await?;
        let res = client
            .query_reference_value(req)
            .await?
            .into_inner()
            .reference_value_results;

        match res {
            Some(reference_value) => {
                let reference_value = serde_json::from_str(&reference_value)?;
                Ok(Some(reference_value))
            }
            None => Ok(None),
        }
    }
}

pub struct GrpcManager {
    address: String,
}

#[async_trait::async_trait]
impl Manager for GrpcManager {
    type Connection = ReferenceValueProviderServiceClient<Channel>;
    type Error = anyhow::Error;

    async fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        let channel = Channel::from_shared(self.address.clone())?
            .keep_alive_while_idle(true)
            .http2_keep_alive_interval(Duration::from_secs(10))
            .keep_alive_timeout(Duration::from_secs(5))
            .connect()
            .await?;
        Ok(ReferenceValueProviderServiceClient::new(channel))
    }

    async fn check(
        &self,
        conn: Self::Connection,
    ) -> std::result::Result<Self::Connection, Self::Error> {
        let mut c = conn;
        // Use a non-empty placeholder key: RVPS returns Ok(None) for unknown keys,
        // confirming the connection is live without triggering an "Is a directory"
        // error that would cause an unnecessary reconnect on every pool.get() call.
        let req = tonic::Request::new(ReferenceValueQueryRequest {
            reference_value_id: "__healthcheck__".to_string(),
        });
        match tokio::time::timeout(Duration::from_secs(1), c.query_reference_value(req)).await {
            Ok(Ok(_)) => Ok(c),
            Ok(Err(e)) => {
                warn!("RVPS connection health check failed, reconnecting: {e}");
                Err(anyhow::anyhow!("stale connection: {e}"))
            }
            Err(_) => {
                warn!("RVPS connection health check timed out, reconnecting");
                Err(anyhow::anyhow!("RVPS health check timed out"))
            }
        }
    }
}
