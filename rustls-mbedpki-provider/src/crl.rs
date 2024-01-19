use crate::alloc::string::ToString;
use std::vec::Vec;
use x509_parser::extensions::CRLDistributionPoints;
type RustlResult<T> = Result<T, rustls::Error>;

/// CrlDownloader trait. Used by `ClientServerVerifier` and `ServerCertVerifier`
pub trait CrlDownloader {
    fn download_crl_for_distribution_points(&self, distribtuion_points: &CRLDistributionPoints<'_>) -> RustlResult<Option<Vec<u8>>>;
}

pub struct CrlDownloaderFromFileDownloader<F: FnMut(&str) -> RustlResult<Vec<u8>>> {
    file_downloader: F,
}

impl<F: FnMut(&str) -> RustlResult<Vec<u8>>> CrlDownloader for CrlDownloaderFromFileDownloader<F> {
    fn download_crl_for_distribution_points(&self, distribtuion_points: &CRLDistributionPoints<'_>) -> RustlResult<Option<Vec<u8>>> {
        let url = distribtuion_points.points.iter().find_map(|dp| {
            if let Some(dp_name) = dp.distribution_point {
                match dp_name {
                    x509_parser::extensions::DistributionPointName::FullName(n) => {
                        n.iter().find_map(|n| {
                            match n {
                                x509_parser::extensions::GeneralName::URI(uri) => Some(uri.to_string()),
                                _ => None
                            }
                        })
                    },
                    x509_parser::extensions::DistributionPointName::NameRelativeToCRLIssuer(rn) => {
                        
                    },
                }
            } else {
                None
            }
        });
        todo!()
    }
}
