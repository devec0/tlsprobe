use clap::{App, Arg, crate_version};

use tokio::fs::File;
use tokio::io::{BufReader, AsyncBufReadExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::{ServerCertVerifier, ServerCertVerified};
use tokio_rustls::rustls::{
    ClientConfig, ServerName, Certificate, RootCertStore, OwnedTrustAnchor
};

use webpki_roots::*;
use x509_parser::prelude::*;

use std::process::exit;
use std::str::FromStr;
use std::time::SystemTime;
use std::net::SocketAddr;
use std::error;
use std::sync::Arc;

use url::Url;

use fern::colors::{Color, ColoredLevelConfig};
use log::*;

struct SkipCertificationVerification;      
                                                                                          
impl ServerCertVerifier for SkipCertificationVerification {                              
    fn verify_server_cert(
        &self,                              
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],                   
        now: SystemTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())                              
    }
} 

pub async fn do_tls_probe(dest: SocketAddr, subdomain: ServerName) -> Result<Vec<String>, Box<dyn error::Error>> {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(
        TLS_SERVER_ROOTS
            .0     
            .iter()       
            .map(|ta| {                                                                   
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,                                                           
                    ta.spki,
                    ta.name_constraints,
                )                  
            }),                              
    );
    let mut tls_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tls_config.dangerous().set_certificate_verifier(Arc::new(SkipCertificationVerification {}));
    
    let tls_connector = TlsConnector::from(Arc::new(tls_config));
    
    match TcpStream::connect(&dest).await {
	Ok(tls_socket) => {
	    info!("TLS connect OK for {:?} with subdomain {:?}", dest, subdomain);
	    if tls_socket.set_nodelay(true).is_ok() {
		debug!("Set TCP nodelay on TLS socket OK");
	    } else {
		debug!("failed to set TCP nodelay on TLS socket");
	    }
	    match tls_connector.connect(subdomain.clone(), tls_socket).await {
		Ok(handshake) => {
		    info!("TLS handshake OK with {:?} subdomain {:?}", dest, subdomain);
		    let (_tcp_stream, client_connection) = handshake.into_inner();
		    if let Some(certs) = client_connection.peer_certificates() {
			// we have a cert! we need to parse it now
			let mut subjects: Vec<String> = vec![];
			for cert in certs {
			    if let Ok((_cert_data, cert_parsed)) = parse_x509_certificate(&cert.0) {
				for subject in cert_parsed.subject().iter_common_name() {
				    if let Ok(subject) = subject.attr_value().as_str() {
					debug!("found subject {} for {:?}, {:?}", subject, dest, subdomain);
					subjects.push(subject.to_string());
				    }
				}
				if let Ok(Some(san)) = cert_parsed.subject_alternative_name() {
				    let san_ext = san.value.clone();
				    for san_item in san_ext.general_names {
					if let GeneralName::DNSName(dns_name) = san_item {
					    debug!("found SAN {} for {:?}, {:?}", dns_name, dest, subdomain);
					    subjects.push(dns_name.to_string());
					}
				    }
				}
			    }
			}
			info!("found subjects from TLS probe: {:?}", subjects);
			Ok(subjects)
		    } else {
			warn!("no TLS certificates returned for {:?} subdomain {:?}", dest, subdomain);
			Ok(Vec::new())
		    }
		},
		Err(e) => {
		    warn!("failed TCP handshake with {:?} subdomain {:?}", dest, subdomain);
		    Err(Box::new(e))
		}
	    }
	},
	Err(e) => {
	    warn!("failed TCP dial, TLS connect for {:?}", dest);
	    Err(Box::new(e))
	}
    }
}


#[tokio::main]
async fn main() {

    let _fern = fern::Dispatch::new()
	.format(|out, message, record| {
	    let colors = ColoredLevelConfig::new()
		.info(Color::Green)
		.warn(Color::Yellow)
		.error(Color::Red)
		.debug(Color::White);

            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
		colors.color(record.level()),
                record.target(),
                message
            ))
	})
	.level(log::LevelFilter::Debug)
	.chain(std::io::stderr())
	.apply().unwrap();
    
    //Set up our app
    let args = App::new("tlsprobe")
	.version(crate_version!())
	.about("Probe TLS details for a provided host and port")
	.args(&[
	    Arg::with_name("host")
		.help("Host to use when indicating TLS hostname")
		.value_name("HOST")
		.short("h")
		.long("host"),
	    Arg::with_name("ip")
		.help("IP to connect to")
		.value_name("IP")
		.short("i")
		.long("ip"),
	    Arg::with_name("port")
		.help("Port to connect on")
		.value_name("PORT")
		.short("p")
		.long("port")
		.default_value("443"),
	    Arg::with_name("urls")
		.help("Path to text file with a list of URIs, only https URIs will be probed.")
		.value_name("URLS")
		.short("u")
		.long("urls")
		.required(false)
	])
	.get_matches();

    let mut url_list: Vec<String> = vec![];
    if let Some(urls) = args.value_of("urls") {
	// we have urls, load file, and check each line for an https uri
	let url_file = File::open(urls).await.expect("failed to open file");
    	let url_reader = BufReader::new(url_file);
	let mut raw_urls = url_reader.lines();
	// add to list if they match
	while let Some(url_line) = raw_urls.next_line().await.expect("Failed to read URI from file") {
            if url_line.starts_with("https") { url_list.push(url_line); }
	}
    } else {
	let port: i32 = match args.value_of("port") {
	    Some(port) => {
		match port.parse::<i32>() {
		    Ok(port) => port,
		    Err(e) => {
			error!("could not parse port {}: {:?}", port, e);
			exit(1);
		    }
		}
	    },
	    None => 443
	};
	
	let ip = match args.value_of("ip") {
	    Some(ip) => ip,
	    None => {
		error!("neither URL list or target IP was provided");
		exit(1);
	    }
	};
	
	url_list.push(format!("https://{ip}:{port}"));
    }

    for url in url_list {

	match Url::parse(&url) {
	    Ok(url_obj) => {

		let port = url_obj.port().unwrap_or(443);
		
		if let Some(host) = url_obj.host() {
		    let host = host.to_string();
		    let servername = match ServerName::try_from("localhost") {
			Ok(server_name) => server_name,
			Err(e) => {
			    error!("Failed to get ServerName: {:?}", e);
			    continue
			}
		    };

		    let target = format!("{}:{}", host, port);
		    let target_str = target.as_str();
		    let target_sockaddr: SocketAddr = match SocketAddr::from_str(target_str) {
			Ok(target) => target,
			Err(e) => {
			    error!("Failed to parse target from {}:{}: {:?}", host, port, e);
			    continue
			}
		    };

		    match do_tls_probe(target_sockaddr, servername).await {
			Ok(results) => {
			    for result in results {
				if result.contains('.') {
				    println!("{host}:{port} {result}");
				}
			    }
			},
			Err(e) => {
			    error!("Failed to perform TLS probe: {:?}", e);
			    continue
			}
		    };
		}
	    },
	    Err(e) => {
		error!("Failed to parse URL {}: {:?}", url, e);
		continue
	    },
	}
    }
}
