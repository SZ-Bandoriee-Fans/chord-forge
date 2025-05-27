use std::{error::Error, fmt::Display};

use async_trait::async_trait;
use downcast_rs::{impl_downcast, DowncastSend};
use serde::Deserialize;

#[async_trait(?Send)]
/// Represents a service for detecting AIGC (Artificial Intelligence Generated Content) images.
pub trait AIGCService {
    async fn init(&mut self, config: Box<dyn APIClientConfig>) -> Result<(), Box<dyn Error>>;
    async fn detect(&self, params: Box<dyn APIClientParams>) -> Result<Box<dyn APIClientResponse>, Box<dyn Error>>;

}


/// Represents the configuration required for an AIGC image detection API client.
pub trait APIClientConfig: DowncastSend {}
impl_downcast!(APIClientConfig);


/// Represents the parameters required for an AIGC image detection request.
pub trait APIClientParams: DowncastSend {}
impl_downcast!(APIClientParams);


pub trait APIClientResponse: DowncastSend {
    fn risk_level(&self) -> AIGCImgDetectRiskLevel;
}
impl_downcast!(APIClientResponse);


#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum AIGCImgDetectRiskLevel {
    Safe,
    Suspicious,
    Unsafe,
}
