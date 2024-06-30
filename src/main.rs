use std::{collections::HashMap, fs::File, io::Write};

use clap::{command, Parser};
use crypto::{
    aes::{self, KeySize},
    blockmodes::{self},
    buffer::{self, ReadBuffer, WriteBuffer},
};

const EXT_X_VERSION: &str = "#EXT-X-VERSION:";

const EXT_X_TARGETDURATION: &str = "#EXT-X-TARGETDURATION:";

const EXT_X_PLAYLIST_TYPE: &str = "#EXT-X-PLAYLIST-TYPE:";

const EXT_X_MEDIA_SEQUENCE: &str = "#EXT-X-MEDIA-SEQUENCE:";

const EXT_X_KEY: &str = "#EXT-X-KEY:";

const METHOD: &str = "METHOD=";

const URL: &str = "URI=";

const IV: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[derive(Debug, Clone)]
struct Ext {
    version: Option<u32>,
    target_duration: Option<u32>,
    play_list_type: Option<String>,
    media_sequence: Option<u32>,
    key: Option<HashMap<String, String>>,
    uri_list: Option<Vec<String>>,
}

impl Ext {
    fn new() -> Self {
        Self {
            version: None,
            target_duration: None,
            play_list_type: None,
            media_sequence: None,
            key: None,
            uri_list: Some(Vec::new()),
        }
    }

    fn set_version(&mut self, version: u32) {
        self.version = Some(version);
    }

    fn set_target_duration(&mut self, target_duration: u32) {
        self.target_duration = Some(target_duration);
    }

    fn set_play_list_type(&mut self, play_list_type: String) {
        self.play_list_type = Some(play_list_type);
    }

    fn set_media_sequence(&mut self, media_sequence: u32) {
        self.media_sequence = Some(media_sequence);
    }
    fn set_key(&mut self, key: HashMap<String, String>) {
        self.key = Some(key);
    }

    fn set_uri_list(&mut self, uri: String) {
        if let Some(vec) = &mut self.uri_list {
            vec.push(uri);
        } else {
            panic!("error");
        };
    }
}

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct M3u8Command {
    /// m3u8 地址
    #[arg(short, long)]
    m_url: String,

    /// 域名
    #[arg(short, long)]
    domain_name: String,

    /// 本地文件地址
    #[arg(short, long)]
    l_dir: String,

    /// 文件名称
    #[arg(short, long, default_value = "index")]
    file_name: String,

    /// 后缀名
    #[arg(short, long, default_value = ".ts")]
    suffix: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let m3u8 = M3u8Command::parse();
    let mut ext = Ext::new();
    let response = reqwest::get(&m3u8.m_url).await?;
    let text = response.text().await?;
    analyze(&mut ext, text, &m3u8.suffix).await?;
    down_load(&ext, &m3u8).await?;
    Ok(())
}

async fn decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut final_result = Vec::<u8>::new();
    let mut buffer = [0; 819200];
    let mut write_buf = buffer::RefWriteBuffer::new(&mut buffer);
    aes::cbc_decryptor(KeySize::KeySize128, key, &iv, blockmodes::PkcsPadding)
        .decrypt(&mut buffer::RefReadBuffer::new(data), &mut write_buf, true)
        .unwrap();

    final_result.extend(
        write_buf
            .take_read_buffer()
            .take_remaining()
            .iter()
            .map(|&i| i),
    );
    Ok(final_result)
}

async fn analyze(
    ext: &mut Ext,
    m3u8_value: String,
    suffix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    m3u8_value.split("\n").for_each(|line| {
        if line.starts_with(EXT_X_VERSION) {
            let version = acquire_u32(&line, EXT_X_VERSION);
            ext.set_version(version);
        }
        if line.starts_with(EXT_X_TARGETDURATION) {
            let target_duration = acquire_u32(&line, EXT_X_TARGETDURATION);
            ext.set_target_duration(target_duration);
        }

        if line.starts_with(EXT_X_PLAYLIST_TYPE) {
            let play_list_type = acquire_string(&line, EXT_X_PLAYLIST_TYPE);
            ext.set_play_list_type(play_list_type);
        }

        if line.starts_with(EXT_X_MEDIA_SEQUENCE) {
            let media_sequence = acquire_u32(&line, EXT_X_MEDIA_SEQUENCE);
            ext.set_media_sequence(media_sequence);
        }

        if line.starts_with(EXT_X_KEY) {
            let mut key_hash: HashMap<String, String> = HashMap::new();
            line.split(EXT_X_KEY)
                .last()
                .unwrap()
                .split(",")
                .for_each(|key| {
                    if key.starts_with(METHOD) {
                        key_hash.insert(
                            METHOD.to_string(),
                            key.split(METHOD).last().unwrap().to_string(),
                        );
                    }
                    if key.starts_with(URL) {
                        key_hash.insert(
                            URL.to_string(),
                            key.split(URL).last().unwrap().to_string().replace("\"", ""),
                        );
                    }
                });

            ext.set_key(key_hash);
        }

        if line.contains(suffix) {
            ext.set_uri_list(line.to_string());
        }
    });
    Ok(())
}

async fn down_load(ext: &Ext, m3u8: &M3u8Command) -> Result<(), Box<dyn std::error::Error>> {
    let mut path = std::path::PathBuf::new();
    path.push(format!("{}/{}{}", m3u8.l_dir, m3u8.file_name, m3u8.suffix));
    let mut write_file = File::create(path).expect("file not found");

    if let Some(uri_list) = &ext.uri_list {
        if let Some(key_value) = &ext.key {
            let mut count: u32 = 1;
            if key_value.get(METHOD).unwrap().is_empty() || key_value.get(URL).unwrap().is_empty() {
                for uri in uri_list.iter() {
                    let mut buf = request_resource(&m3u8.domain_name, uri).await?;
                    let _ = write_file.write_all(&mut buf).unwrap();
                    println!("{}/{}", count, uri_list.len());
                    count += 1;
                }
            } else {
                let key_resp = reqwest::get(format!(
                    "{}{}",
                    &m3u8.domain_name,
                    key_value.get(URL).unwrap()
                ))
                .await?;
                let key = key_resp.text().await?;
                for uri in uri_list.iter() {
                    let buf = request_resource(&m3u8.domain_name, uri).await?;
                    let mut result = decrypt(key.as_bytes(), &IV, &buf).await?;
                    let _ = write_file.write_all(&mut result).unwrap();
                    println!("{}/{}", count, uri_list.len());
                    count += 1;
                }
            }
        }
    }

    Ok(())
}

async fn request_resource(
    domain_name: &String,
    uri: &String,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let value = reqwest::get(format!("{}/{}", domain_name, uri))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
        .to_vec();
    Ok(value)
}

fn acquire_u32(context: &str, keyword: &str) -> u32 {
    let data = context.split(keyword);
    let value = data.last().unwrap().to_string().parse::<u32>().unwrap();
    value
}

fn acquire_string(context: &str, keyword: &str) -> String {
    let data = context.split(keyword);
    let value = data.last().unwrap().to_string();
    value
}
