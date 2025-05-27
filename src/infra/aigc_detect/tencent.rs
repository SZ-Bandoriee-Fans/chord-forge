use std::error::Error;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::warn;
use url::Url;

use crate::domain::aigc_detect::{AIGCImgDetectRiskLevel, AIGCService, APIClientConfig, APIClientParams, APIClientResponse};

// #[derive(Debug, thiserror::Error)]
#[derive(Debug, thiserror::Error)]
pub enum TecentAIGCDetectError {
    #[error("HMAC error: {0}")]
    HmacError(#[from] hmac::digest::InvalidLength),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("URL parse error: {0}")]
    UrlError(#[from] url::ParseError),
    #[error("Invalid config type, expected TecentAIGCDetectConfig")]
    ConfigTypeError,
    #[error("Invalid params type, expected TecentAIGCDetectParams")]
    ParamsTypeError,
    #[error("Service not initialized")]
    ServiceNotInitialized,
    #[error("API error: {0}")]
    ApiError(String),
    #[error("Downcast to {0} error")]
    DowncastError(String),
}

const API_VERSION: &str = "2020-12-29";

pub mod action {
    pub const IMAGE_MODERATION: &str = "ImageModeration";
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PublicParamsV1 {
    action: String,
    region: Region,
    timestamp: i64,
    nonce: u32,
    secret_id: String,
    signature: String,
    version: String,
}

impl PublicParamsV1 {
    pub fn new(region: Region, secret_id: String) -> Self {
        Self {
            action: action::IMAGE_MODERATION.to_string(),
            region,
            timestamp: chrono::Utc::now().timestamp(),
            nonce: rand::random::<u32>(),
            secret_id,
            signature: "".to_string(),
            version: API_VERSION.to_string(),
        }
    }
    
    fn fields_without_signature(&self) -> Vec<(&str, String)> {
        vec![
            ("Action",      self.action.clone()),
            ("Region",      self.region.to_string()),
            ("Timestamp",   self.timestamp.to_string()),
            ("Nonce",       self.nonce.to_string()),
            ("SecretId",    self.secret_id.clone()),
            ("Version",     self.version.clone()),
        ]
    }

    fn endpoint(&self) -> String {
        format!("ims.{}.tencentcloudapi.com", self.region.to_string())
    }
}

fn query_string(host: &str, http_method: axum::http::Method, mut fields: Vec<(&str, String)>) -> String {
    fields.sort_by(|a, b| a.0.cmp(b.0));
    format!(
        "{}{}/?{}", http_method.as_str(), host,
        fields.into_iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<String>>().join("&")
    )
}

static BASE64_ENGINE: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn hmac_sha1(secret_key: &str, str2sign: String) -> Result<String, TecentAIGCDetectError> {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;

    let mut mac = HmacSha1::new_from_slice(secret_key.as_bytes())?;
    mac.update(str2sign.as_bytes());
    let rs = BASE64_ENGINE.encode(mac.finalize().into_bytes());
    Ok(rs)
}

fn post_body(host: &str, secret_key: &str, public_params: &PublicParamsV1, input_params: &InputParams) -> Result<String, TecentAIGCDetectError> {
    use url::form_urlencoded::byte_serialize as percent_encode;

    let http_method = axum::http::Method::POST;
    let mut fields = public_params.fields_without_signature();
    fields.extend_from_slice(&input_params.fields());

    let query_str = query_string(host, http_method.clone(), fields.clone());
    let signature = hmac_sha1(secret_key, query_str)?;
    fields.push(("Signature", signature));

    let rs = fields.into_iter()
        .map(|(k, v)| format!("{}={}", k, percent_encode(v.as_bytes()).collect::<String>()))
        .collect::<Vec<String>>()
        .join("&");
    Ok(rs)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct InputParams {
    biz_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_id: Option<String>,
    file_url: Url,
}

impl InputParams {
    fn fields(&self) -> Vec<(&str, String)> {
        let mut fields = vec![
            ("BizType", self.biz_type.clone()),
            ("FileUrl", self.file_url.to_string()),
        ];
        if let Some(ref data_id) = self.data_id {
            fields.push(("DataId", data_id.clone()));
        }
        fields
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Region {
    ApBeijing,
    ApGuangzhou,
    ApNanjing,
    ApShanghai,
    ApSingapore,
}

impl ToString for Region {
    fn to_string(&self) -> String {
        match self {
            Region::ApBeijing => "ap-beijing".to_string(),
            Region::ApGuangzhou => "ap-guangzhou".to_string(),
            Region::ApNanjing => "ap-nanjing".to_string(),
            Region::ApShanghai => "ap-shanghai".to_string(),
            Region::ApSingapore => "ap-singapore".to_string(),
        }
    }
}

async fn post(
    public_params: PublicParamsV1,
    input_params: InputParams,
    secret_key: &str,
    http_client: &reqwest::Client,
) -> Result<reqwest::Response, TecentAIGCDetectError> {
    let endpoint = public_params.endpoint();
    let post_url = format!("https://{}", endpoint);
    let body = post_body(&endpoint, secret_key, &public_params, &input_params)?;
    let res = http_client.post(post_url).body(body).send().await?;
    
    Ok(res)
}


#[derive(Debug, Clone, Deserialize)]
pub struct Response {
    #[serde(rename = "Response")]
    pub response: ResponseInner,
}

impl APIClientResponse for Response {
    fn risk_level(&self) -> AIGCImgDetectRiskLevel {
        match self.response.suggestion {
            Suggestion::Block => AIGCImgDetectRiskLevel::Unsafe,
            Suggestion::Review => AIGCImgDetectRiskLevel::Suspicious,
            Suggestion::Pass => AIGCImgDetectRiskLevel::Safe,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResponseInner {
    request_id: String,
    data_id: String,
    hit_flag: u8,
    hit_type: Option<String>,
    suggestion: Suggestion,
    label: String,
    sub_label: String,
    score: u8,
    label_results: Option<Vec<serde_json::Value>>,
    object_results: Option<Vec<serde_json::Value>>,
    ocr_results: Option<Vec<serde_json::Value>>,
    lib_results: Option<Vec<serde_json::Value>>,
    recognition_results: Option<Vec<serde_json::Value>>,
    extra: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub enum Suggestion {
    Block,
    Review,
    Pass,
}

pub struct TecentAIGCDetectService {
    http_client: reqwest::Client,
    config: Option<TecentAIGCDetectConfig>,
}

impl Default for TecentAIGCDetectService {
    fn default() -> Self {
        Self {
            http_client: reqwest::Client::new(),
            config: None,
        }
    }
}

#[async_trait(?Send)]
impl AIGCService for TecentAIGCDetectService {
    async fn init(&mut self, config: Box<dyn APIClientConfig>) -> Result<(), Box<dyn Error>> {
        let config = *config.downcast::<TecentAIGCDetectConfig>()
            .map_err(|_| {
                warn!("downcast TecentAIGCDetectConfig failed");
                TecentAIGCDetectError::DowncastError("config".to_string())
            })?;
        self.config = Some(config);
        Ok(())
    }

    async fn detect(&self, params: Box<dyn APIClientParams>) -> Result<Box<dyn APIClientResponse>, Box<dyn Error>> {
        let params = params.downcast::<TecentAIGCDetectParams>()
            .map_err(|_| {
                warn!("downcast TecentAIGCDetectParams failed");
                TecentAIGCDetectError::DowncastError("params".to_string())
            })?;
        let config = self.config.as_ref().ok_or_else(|| {
            warn!("TecentAIGCDetectService not initialized");
            TecentAIGCDetectError::ServiceNotInitialized
        })?;
        
        let public_params = PublicParamsV1::new(config.region, config.secret_id.clone());
        let input_params = InputParams {
            biz_type:   params.biz_type.clone(),
            data_id:    params.data_id.clone(),
            file_url:   params.file_url.clone(),
        };
        let res_text = post(public_params, input_params, &config.secret_key, &self.http_client).await
            .inspect_err(|e| warn!("TecentAIGCDetectService post error: {}", e))?
            .text().await
            .inspect_err(|e| warn!("TecentAIGCDetectService response text error: {}", e))?;
        let res: Response = serde_json::from_str(&res_text)?;
        Ok(Box::new(res))
    }
}

pub struct TecentAIGCDetectConfig {
    pub secret_id: String,
    pub secret_key: String,
    pub region: Region,
    pub biz_type: String,
}

impl TecentAIGCDetectConfig {
    pub fn set_region(&mut self, region: Region) {
        self.region = region;
    }
}

impl TecentAIGCDetectConfig {
    pub fn new(secret_id: String, secret_key: String, region: Region, biz_type: String) -> Self {
        Self {
            secret_id,
            secret_key,
            region,
            biz_type
        }
    }
    
}

impl APIClientConfig for TecentAIGCDetectConfig {}

pub struct TecentAIGCDetectParams {
    pub biz_type: String,
    pub data_id: Option<String>,
    pub file_url: Url,
}

impl APIClientParams for TecentAIGCDetectParams {}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    #[ignore = "real request, requires valid credentials"]
    async fn test_manual() {
        let id = std::env::var("TECENT_AIGC_DETECT_ID").expect("TECENT_AIGC_DETECT_ID must be set");
        let key = std::env::var("TECENT_AIGC_DETECT_KEY").expect("TECENT_AIGC_DETECT_KEY must be set");
        let img_url = std::env::var("TECENT_AIGC_DETECT_IMG_URL").expect("TECENT_AIGC_DETECT_IMG_URL must be set");
        let public_params = PublicParamsV1::new(Region::ApGuangzhou, id.to_string());
        let input_params = InputParams {
            biz_type: "aigc_image_detect_100028798466".to_string(),
            data_id: Some(uuid::Uuid::new_v4().to_string()),
            file_url: Url::parse(&img_url).unwrap(),
        };
        let post_body = post_body(&public_params.endpoint(), &key, &public_params, &input_params).unwrap();
        println!("post_url: {}", post_body);
        let http_client = reqwest::Client::new();
        let res = post(public_params, input_params, &key, &http_client).await.unwrap();
        println!("url: {}", res.url());
        let text = res.text().await.unwrap();
        println!("res: {}", text);
    }

    #[test]
    fn test_response_deserialize() {
        let json = r#"{"Response":{"RequestId":"example-request-id","DataId":"6bf4a661-e072-490a-b1f2-727ab59a2d1b","BizType":"aigc_image_detect_xxxxxxxxxx","FileMD5":"1f9fbf92661eebc92b99b089f12e525a","HitFlag":1,"HitType":"image_youtu_model","Suggestion":"Block","Label":"Teenager","SubLabel":"ACGMinors","SubTag":"ACGMinors","Score":96,"LabelResults":[{"HitFlag":1,"HitType":"image_youtu_model","Scene":"Teenager","Suggestion":"Block","Label":"Teenager","SubLabel":"ACGMinors","SubTag":"ACGMinors","Score":96,"Details":[{"Id":0,"Name":"ACGMinors","Score":96}]},{"HitFlag":0,"HitType":"","Scene":"Porn","Suggestion":"Pass","Label":"Normal","SubLabel":"","SubTag":"","Score":0,"Details":[]},{"HitFlag":0,"HitType":"","Scene":"GeneratedContentRisk","Suggestion":"Pass","Label":"Normal","SubLabel":"","SubTag":"","Score":11,"Details":[]}],"ObjectResults":[{"HitFlag":0,"HitType":"","Scene":"PolityFace","Suggestion":"Pass","Label":"Normal","SubLabel":"","SubTag":"","Score":0,"Names":[],"Details":[]}],"OcrResults":[],"LibResults":[],"RecognitionResults":[],"Extra":"{}"},"retcode":0,"retmsg":"ok"}"#;
        serde_json::from_str::<Response>(json).unwrap();
    }
}
