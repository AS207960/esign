use std::io::Write;
use std::ptr::null_mut;
use foreign_types_shared::{ForeignType, ForeignTypeRef};
use bcder::encode::Values;
use asn1::SimpleAsn1Writable;

#[repr(C)]
pub struct CMS_ContentInfo {
    pub version: libc::c_long,
    pub sid: *mut openssl_sys::CMS_SignerIdentifier,
    pub digest_algorithm: *mut openssl_sys::X509_ALGOR,
    pub signed_attributes: *mut openssl_sys::stack_st_X509_ATTRIBUTE,
    pub signature_algorithm: *mut openssl_sys::X509_ALGOR,
    pub signature: *mut openssl_sys::ASN1_OCTET_STRING,
    pub unsigned_attributes: *mut openssl_sys::stack_st_X509_ATTRIBUTE,
    pub signer: *mut openssl_sys::X509,
    pub pkey: *mut openssl_sys::EVP_PKEY,
}

fn cvt_p<T>(r: *mut T) -> Result<*mut T, openssl::error::ErrorStack> {
    if r.is_null() {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt(r: libc::c_int) -> Result<libc::c_int, openssl::error::ErrorStack> {
    if r <= 0 {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

pub struct Document {
    inner_doc: lopdf::Document,
    font_id: Option<lopdf::ObjectId>,
    pages: std::collections::BTreeMap<u32, lopdf::ObjectId>,
    new_objects: std::collections::btree_map::BTreeMap::<lopdf::ObjectId, lopdf::Object>,
    max_id: u32,
    base_file_bytes: Vec<u8>,
}

struct BoundingBox {
    ll: (f64, f64),
    ur: (f64, f64),
}

struct PDFSpacePos {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
}

pub struct DocumentPage<'a> {
    page_id: lopdf::ObjectId,
    page: lopdf::Dictionary,
    inner_content: lopdf::content::Content,
    doc: &'a mut Document,
}

pub struct InnerDocumentPage<'a: 'b, 'b> {
    page_id: lopdf::ObjectId,
    page: &'b mut lopdf::Dictionary,
    inner_content: lopdf::content::Content,
    resources_oid: Option<lopdf::ObjectId>,
    pub doc: &'a mut Document,
}

pub struct SigningInfo {
    pub name: Option<String>,
    pub date: Option<chrono::DateTime<chrono::Utc>>,
    pub location: Option<String>,
    pub reason: Option<String>,
    pub contact_info: Option<String>,
    pub top: f64,
    pub left: f64,
    pub width: f64,
    pub height: f64,
    pub img_obj_id: lopdf::ObjectId
}

pub struct SigningFinalisationInfo {
    pub oid: lopdf::ObjectId,
    pub keys: crate::SigningInfo,
}

impl Document {
    pub fn new(doc: lopdf::Document, base_file_bytes: &[u8]) -> Self {
        Self {
            pages: doc.get_pages(),
            max_id: doc.max_id,
            inner_doc: doc,
            font_id: None,
            new_objects: std::collections::btree_map::BTreeMap::new(),
            base_file_bytes: base_file_bytes.to_owned(),
        }
    }

    pub async fn finalise(mut self, sig_info: Option<SigningFinalisationInfo>) -> Result<Vec<u8>, lopdf::Error> {
        let mut target = lopdf::writer::CountingWrite {
            bytes_written: self.base_file_bytes.len(),
            inner: &mut self.base_file_bytes,
        };
        let mut trailer = self.inner_doc.trailer.clone();
        let is_xref_stream = trailer.get(b"Type").ok().and_then(|t| t.as_name().ok()) == Some(b"XRef");
        let mut xref = lopdf::xref::Xref::new(self.new_objects.len() as u32);

        let mut contents_map = Some(std::collections::btree_map::BTreeMap::<lopdf::ObjectId, (u32, u32)>::new());
        for (&oid, object) in &self.new_objects {
            if object
                .type_name()
                .map(|name| ["ObjStm", "XRef", "Linearized"].contains(&name))
                .ok()
                != Some(true)
            {
                contents_map = lopdf::writer::Writer::write_indirect_object(&mut target, oid, object, &mut xref, contents_map)?;
            }
        }
        let contents_map = contents_map.unwrap();

        let xref_start = target.bytes_written;
        println!("{:?} {:?}", trailer, xref);
        if is_xref_stream {
            self.max_id += 1;
            let xref_id = (self.max_id, 0);
            xref.insert(xref_id.0, lopdf::xref::XrefEntry::Normal { offset: xref_start as u32, generation: xref_id.1 });
            let (xref_content, xref_indices) = lopdf::writer::Writer::write_xref_stream(&xref);
            lopdf::writer::Writer::write_indirect_object(&mut target, xref_id, &lopdf::Object::Stream(lopdf::Stream {
                dict: lopdf::dictionary! {
                    "Type" => "XRef",
                    "Size" => i64::from(self.max_id + 1),
                    "Prev" => self.inner_doc.reference_table_start as i64,
                    "W" => lopdf::Object::Array(vec![lopdf::Object::Integer(1), lopdf::Object::Integer(4), lopdf::Object::Integer(2)]),
                    "Root" => trailer.get(b"Root")?.to_owned(),
                    "Info" => trailer.get(b"Info")?.to_owned(),
                    "ID" => trailer.get(b"ID")?.to_owned(),
                    "Length" => lopdf::Object::Integer(xref_content.len() as i64),
                    "Index" => lopdf::Object::Array(
                        xref_indices.into_iter().map(|i| vec![lopdf::Object::Integer(i.0), lopdf::Object::Integer(i.1)])
                        .fold(vec![], |a, b| a.into_iter().chain(b.into_iter()).collect())
                    )
                },
                content: xref_content,
                allows_compression: true,
                start_position: Some(xref_start)
            }), &mut xref, None)?;
        } else {
            lopdf::writer::Writer::write_xref(&mut target, &xref)?;
            trailer.set(*b"Size", i64::from(self.max_id + 1));
            trailer.set(*b"Prev", self.inner_doc.reference_table_start as i64);
            trailer.remove(b"Type");
            target.write_all(b"trailer\n").unwrap();
            lopdf::writer::Writer::write_dictionary(&mut target, &trailer, None, None)?;
        }

        write!(target, "\nstartxref\n{}\n%%EOF", xref_start).unwrap();

        if let Some(sig_info) = sig_info {
            let contents_range = *contents_map.get(&sig_info.oid).unwrap();
            self.base_file_bytes[contents_range.1 as usize + 10] = b'[';
            self.base_file_bytes.splice(
                contents_range.1 as usize + 12..contents_range.1 as usize + 45,
                format!(" {:010} {:010} {:010}", contents_range.0, contents_range.1, self.base_file_bytes.len() - contents_range.1 as usize).bytes()
            );
            self.base_file_bytes[contents_range.1 as usize + 45] = b']';

            let signed_bytes = self.base_file_bytes[..contents_range.0 as usize].iter().cloned().chain(
                self.base_file_bytes[contents_range.1 as usize..].iter().cloned()
            ).collect::<Vec<_>>();

             let signature_bytes = match match tokio::task::spawn_blocking(
                move || -> Result<Vec<u8>, String> {
                    let signed_bytes_bio = openssl::bio::MemBioSlice::new(&signed_bytes).map_err(|e| e.to_string())?;
                    let flags = openssl::cms::CMSOptions::DETACHED | openssl::cms::CMSOptions::BINARY |
                        openssl::cms::CMSOptions::NOSMIMECAP | openssl::cms::CMSOptions::CADES |
                        openssl::cms::CMSOptions::PARTIAL;
                    Ok(unsafe {
                        let cms = cvt_p(openssl_sys::CMS_sign(
                            null_mut(), null_mut(), null_mut(),
                            signed_bytes_bio.as_ptr(), flags.bits()
                        )).map_err(|e| e.to_string())?;
                        for cert in &sig_info.keys.signing_cert_chain {
                            cvt(openssl_sys::CMS_add0_cert(cms, cert.as_ptr())).map_err(|e| e.to_string())?;
                        }
                        let si = cvt_p(openssl_sys::CMS_add1_signer(
                            cms, sig_info.keys.signing_cert.as_ptr(), sig_info.keys.signing_pkey.as_ptr(),
                            openssl_sys::EVP_sha256(), flags.bits()
                        )).map_err(|e| e.to_string())?;

                        let certificate_hash =
                            sig_info.keys.signing_cert.digest(openssl::hash::MessageDigest::sha256()).map_err(|e| e.to_string())?;
                        let certificate_hash_sha1 =
                            sig_info.keys.signing_cert.digest(openssl::hash::MessageDigest::sha1()).map_err(|e| e.to_string())?;
                        let sn = sig_info.keys.signing_cert.serial_number();
                        let sn_len = cvt(openssl_sys::i2d_ASN1_INTEGER(sn.as_ptr(), std::ptr::null_mut()))
                            .map_err(|e| e.to_string())?;
                        let mut sn_buf = vec![0u8; sn_len as usize];
                        cvt(openssl_sys::i2d_ASN1_INTEGER(sn.as_ptr(), &mut sn_buf.as_mut_ptr()))
                            .map_err(|e| e.to_string())?;
                        let signing_cert_bytes = asn1::write(|w| {
                            w.write_element(&asn1::SequenceWriter::new(&|w| {
                                w.write_element(&asn1::SequenceWriter::new(&|w| {
                                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                                        w.write_element(&certificate_hash.to_vec().as_slice())?;
                                        w.write_element(&asn1::SequenceWriter::new(&|w| {
                                            w.write_element(&asn1::SequenceWriter::new(&|w| {
                                                w.write_tlv(asn1::Tag::from_bytes(&[0xa4]).unwrap().0, |b| {
                                                    b.push_slice((*sig_info.keys.signing_cert.issuer_name()).to_der().unwrap().as_slice())?;
                                                    Ok(())
                                                })
                                            }))?;
                                            w.write_element(&asn1::BigInt::new(&sn_buf[2..]))
                                        }))
                                    }))
                                }))
                            }))
                        }).map_err(|e| format!("{:?}", e))?;
                            sig_info.keys.signing_cert.digest(openssl::hash::MessageDigest::sha1()).map_err(|e| e.to_string())?;
                        let signing_cert_bytes_v1 = asn1::write(|w| {
                            w.write_element(&asn1::SequenceWriter::new(&|w| {
                                w.write_element(&asn1::SequenceWriter::new(&|w| {
                                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                                        w.write_element(&certificate_hash_sha1.to_vec().as_slice())?;
                                        w.write_element(&asn1::SequenceWriter::new(&|w| {
                                            w.write_tlv(asn1::Tag::from_bytes(&[0x4a]).unwrap().0, |b| {
                                                asn1::Writer::new(b).write_element(&asn1::SequenceWriter::new(&|w| {
                                                    w.write_tlv(asn1::Sequence::TAG, |b| {
                                                        b.push_slice((*sig_info.keys.signing_cert.issuer_name()).to_der().unwrap().as_slice())?;
                                                        Ok(())
                                                    })
                                                }))
                                            })?;
                                            w.write_element(&asn1::BigInt::new(
                                                &sig_info.keys.signing_cert.serial_number().to_bn().unwrap().to_vec()
                                            ))
                                        }))
                                    }))
                                }))
                            }))
                        }).map_err(|e| format!("{:?}", e))?;
                        openssl_sys::CMS_signed_add1_attr_by_OBJ(
                            si, openssl::asn1::Asn1Object::from_str("1.2.840.113549.1.9.16.2.47").unwrap().as_ptr(),
                            16, signing_cert_bytes.as_ptr() as *const libc::c_void, signing_cert_bytes.len() as i32
                        );
                        // openssl_sys::CMS_signed_add1_attr_by_OBJ(
                        //     si, openssl::asn1::Asn1Object::from_str("1.2.840.113549.1.9.16.2.12").unwrap().as_ptr(),
                        //     16, signing_cert_bytes_v1.as_ptr() as *const libc::c_void, signing_cert_bytes_v1.len() as i32
                        // );

                        cvt(openssl_sys::CMS_final(
                            cms, signed_bytes_bio.as_ptr(), null_mut(), flags.bits()
                        )).map_err(|e| e.to_string())?;
                        let sig: &[u8] = std::slice::from_raw_parts(
                            openssl_sys::ASN1_STRING_get0_data((*(si as *const CMS_ContentInfo)).signature as *const openssl_sys::ASN1_STRING),
                            openssl_sys::ASN1_STRING_length((*(si as *const CMS_ContentInfo)).signature as *const openssl_sys::ASN1_STRING) as usize
                        );
                        let r = cryptographic_message_syntax::time_stamp_message_http(
                            "http://dd-at.ria.ee/tsa", &sig,
                            x509_certificate::DigestAlgorithm::Sha256
                        ).map_err(|e| format!("Unable to get timestamp: {}", e))?;
                        if !r.is_success() {
                            return Err("Unable to get timestamp, unknown error".to_string());
                        }
                        let rs = r.signed_data().map_err(|e| e.to_string())?.ok_or("Signed timestamp not available")?;
                        let rsd = rs.encode_ref().to_captured(bcder::Mode::Der);
                        let rsds = rsd.as_slice();
                        cvt(openssl_sys::CMS_unsigned_add1_attr_by_NID(
                            si, openssl::nid::Nid::ID_SMIME_AA_TIMESTAMPTOKEN.as_raw(),
                            16, rsds.as_ptr() as *const libc::c_void, rsds.len() as i32
                        )).map_err(|e| e.to_string())?;
                        let l = cvt(openssl_sys::i2d_CMS_ContentInfo(cms, null_mut())).map_err(|e| e.to_string())?;
                        let mut buf = vec![0; l as usize];
                        cvt(openssl_sys::i2d_CMS_ContentInfo(cms, &mut buf.as_mut_ptr())).map_err(|e| e.to_string())?;
                        buf
                    })
                }
            ).await {
                 Ok(s) => s,
                 Err(err) => {
                     return Err(lopdf::Error::IO(err.into()));
                 }
             } {
                 Ok(s) => s,
                 Err(err) => {
                     return Err(lopdf::Error::IO(std::io::Error::new(std::io::ErrorKind::Other, err)));
                 }
             };

            for i in 0..signature_bytes.len() {
                let b_str = format!("{:02x}", signature_bytes[i]);
                let b = b_str.as_bytes();
                self.base_file_bytes[contents_range.0 as usize + 1 + (2*i)] = b[0];
                self.base_file_bytes[contents_range.0 as usize + 2 + (2*i)] = b[1];
            }

        }

        Ok(self.base_file_bytes)
    }

    pub fn page(&mut self, page: u32) -> Result<DocumentPage, lopdf::Error> {
        let page_id = match self.pages.get(&page).map(|o| *o) {
            Some(i) => i,
            None => return Err(lopdf::Error::PageNumberNotFound(page))
        };

        Ok(DocumentPage {
            inner_content: self.inner_doc.get_and_decode_page_content(page_id)?,
            page: self.inner_doc.get_object(page_id).and_then(lopdf::Object::as_dict).unwrap().clone(),
            doc: self,
            page_id,
        })
    }

    pub fn png_to_xobj(&mut self, data: &[u8]) -> Result<lopdf::ObjectId, lopdf::Error> {
        let img = png::Decoder::new(data);
        let mut img_reader = match img.read_info() {
            Ok(i) => i,
            Err(e) => return Err(Self::png_error_to_lopdf(e))
        };
        let mut img_buf = vec![0; img_reader.output_buffer_size()];
        let img_data = match img_reader.next_frame(&mut img_buf) {
            Ok(i) => i,
            Err(e) => return Err(Self::png_error_to_lopdf(e))
        };
        let img_bytes = &img_buf[..img_data.buffer_size()];

        let (img_bytes, img_bytes_format, bits_per_component, mask_bytes) = match img_data.bit_depth {
            png::BitDepth::One => {
                match img_data.color_type {
                    png::ColorType::Grayscale => {
                        (img_bytes.to_vec(), "DeviceGray", 1, None)
                    }
                    png::ColorType::Rgb => {
                        (img_bytes.to_vec(), "DeviceRGB", 1, None)
                    }
                    _ => return Err(lopdf::Error::IO(std::io::ErrorKind::Unsupported.into()))
                }
            }
            png::BitDepth::Two => {
                match img_data.color_type {
                    png::ColorType::Grayscale => {
                        (img_bytes.to_vec(), "DeviceGray", 2, None)
                    }
                    png::ColorType::Rgb => {
                        (img_bytes.to_vec(), "DeviceRGB", 2, None)
                    }
                    _ => return Err(lopdf::Error::IO(std::io::ErrorKind::Unsupported.into()))
                }
            }
            png::BitDepth::Four => {
                match img_data.color_type {
                    png::ColorType::Grayscale => {
                        (img_bytes.to_vec(), "DeviceGray", 4, None)
                    }
                    png::ColorType::Rgb => {
                        (img_bytes.to_vec(), "DeviceRGB", 4, None)
                    }
                    _ => return Err(lopdf::Error::IO(std::io::ErrorKind::Unsupported.into()))
                }
            }
            png::BitDepth::Eight => {
                match img_data.color_type {
                    png::ColorType::Grayscale => {
                        (img_bytes.to_vec(), "DeviceGray", 8, None)
                    }
                    png::ColorType::Rgb => {
                        (img_bytes.to_vec(), "DeviceRGB", 8, None)
                    }
                    png::ColorType::GrayscaleAlpha => {
                        let mut gray_bytes = Vec::with_capacity(img_bytes.len() / 2);
                        let mut alpha_bytes = Vec::with_capacity(img_bytes.len() / 2);

                        for (i, byte) in img_bytes.iter().enumerate() {
                            if i % 2 == 0 {
                                gray_bytes.push(*byte);
                            } else {
                                alpha_bytes.push(*byte);
                            }
                        }

                        (gray_bytes, "DeviceGray", 8, Some(alpha_bytes))
                    }
                    png::ColorType::Rgba => {
                        let mut rgb_bytes = Vec::with_capacity((img_bytes.len() / 4) * 3);
                        let mut alpha_bytes = Vec::with_capacity(img_bytes.len() / 4);

                        for (i, byte) in img_bytes.iter().enumerate() {
                            if i % 4 == 3 {
                                alpha_bytes.push(*byte);
                            } else {
                                rgb_bytes.push(*byte);
                            }
                        }

                        (rgb_bytes, "DeviceRGB", 8, Some(alpha_bytes))
                    }
                    _ => return Err(lopdf::Error::IO(std::io::ErrorKind::Unsupported.into()))
                }
            }
            _ => return Err(lopdf::Error::IO(std::io::ErrorKind::Unsupported.into()))
        };

        let mut img_zlib_encoder = deflate::write::ZlibEncoder::new(Vec::new(), deflate::Compression::Default);
        img_zlib_encoder.write_all(&img_bytes).unwrap();
        let compressed_img_data = img_zlib_encoder.finish().unwrap();
        let mut img_hex_data = hex::encode(&compressed_img_data);
        img_hex_data.push('>');

        let mask_obj_id = mask_bytes.map(|mask_bytes| {
            let mut mask_zlib_encoder = deflate::write::ZlibEncoder::new(Vec::new(), deflate::Compression::Default);
            mask_zlib_encoder.write_all(&mask_bytes).unwrap();
            let compressed_mask_data = mask_zlib_encoder.finish().unwrap();
            let mut mask_hex_data = hex::encode(&compressed_mask_data);
            mask_hex_data.push('>');

            let mut mask_dict = dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "ColorSpace" => "DeviceGray",
                "Width" => lopdf::Object::Integer(img_data.width.into()),
                "Height" => lopdf::Object::Integer(img_data.height.into()),
                "BitsPerComponent" => lopdf::Object::Integer(bits_per_component),
                "Filter" => lopdf::Object::Array(vec!["ASCIIHexDecode".into(), "FlateDecode".into()])
            };
            let mask_obj = lopdf::Stream::new(mask_dict, mask_hex_data.into())
                .with_compression(false);
            self.max_id += 1;
            let oid = (self.max_id, 0);
            self.new_objects.insert(oid, mask_obj.into());
            oid
        });

        let mut img_dict = dictionary! {
            "Type" => "XObject",
            "Resources" => dictionary! {},
            "Subtype" => "Image",
            "ColorSpace" => img_bytes_format,
            "Width" => lopdf::Object::Integer(img_data.width.into()),
            "Height" => lopdf::Object::Integer(img_data.height.into()),
            "BitsPerComponent" => lopdf::Object::Integer(bits_per_component),
            "Filter" => lopdf::Object::Array(vec!["ASCIIHexDecode".into(), "FlateDecode".into()])
        };
        if let Some(mask_obj_id) = mask_obj_id {
            img_dict.set("SMask", lopdf::Object::Reference(mask_obj_id.into()));
        }
        let img_obj = lopdf::Stream::new(img_dict, img_hex_data.into())
            .with_compression(false);

        self.max_id += 1;
        let img_obj_id = (self.max_id, 0);
        self.new_objects.insert(img_obj_id.clone(), img_obj.into());

        Ok(img_obj_id)
    }

    // fn page_dict(&mut self, page: u32) -> Result<&mut lopdf::Dictionary, lopdf::Error> {
    //     let page_id = match self.pages.get(&page).map(|o| *o) {
    //         Some(i) => i,
    //         None => return Err(lopdf::Error::PageNumberNotFound(page))
    //     };
    //
    //     if !self.new_objects.contains_key(&page_id) {
    //         let page = self.inner_doc.get_object(page_id).and_then(lopdf::Object::as_dict).unwrap().clone();
    //         self.new_objects.insert(page_id, page.into());
    //     }
    //
    //     Ok(self.new_objects.get_mut(&page_id).unwrap().as_dict_mut().unwrap())
    // }

    fn png_error_to_lopdf(err: png::DecodingError) -> lopdf::Error {
        match err {
            png::DecodingError::IoError(io) => lopdf::Error::IO(io),
            png::DecodingError::Format(f) => lopdf::Error::Syntax(f.to_string()),
            png::DecodingError::Parameter(f) => lopdf::Error::Syntax(f.to_string()),
            png::DecodingError::LimitsExceeded => lopdf::Error::IO(std::io::ErrorKind::OutOfMemory.into())
        }
    }

    fn create_or_get_font_id(&mut self) -> lopdf::ObjectId {
        match self.font_id {
            Some(f) => f,
            None => {
                self.max_id += 1;
                let font_id = (self.max_id, 0);
                self.new_objects.insert(font_id, dictionary! {
                    "Type" => "Font",
                    "Subtype" => "Type1",
                    "BaseFont" => "Helvetica",
                }.into());
                self.font_id = Some(font_id);
                font_id
            }
        }
    }

    fn acro_form(&mut self) -> Result<&mut lopdf::Dictionary, lopdf::Error> {
        let catalog = self.inner_doc.catalog()?;

        let acro_form = if catalog.has(b"AcroForm") {
            let r = catalog.get(b"AcroForm").unwrap();
            if let Ok(r) = r.as_reference() {
                let o = self.inner_doc.get_object(r).unwrap().clone();
                self.new_objects.insert(r, o);
                self.new_objects.get_mut(&r).unwrap()
            } else {
                let c = catalog.clone();
                let root = self.inner_doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
                self.new_objects.insert(root, c.into());
                self.new_objects.get_mut(&root).unwrap().as_dict_mut().unwrap().get_mut(b"AcroForm").unwrap()
            }
        } else {
            self.max_id += 1;
            let afid = (self.max_id, 0);
            self.new_objects.insert(afid, dictionary! {
                "ProcSet" => lopdf::Object::Array(vec![lopdf::Object::Name(b"PDF".to_vec()), lopdf::Object::Name(b"Text".to_vec())])
            }.into());

            let mut c = catalog.clone();
            c.set("AcroForm", lopdf::Object::Reference(afid));
            let root = self.inner_doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
            self.new_objects.insert(root, c.into());
            self.new_objects.get_mut(&afid).unwrap()
        }.as_dict_mut().unwrap();

        Ok(acro_form)
    }

    fn get_inherited_attr(&self, key: &[u8], page_id: lopdf::ObjectId) -> Result<&lopdf::Object, lopdf::Error> {
        fn get_key<'a>(key: &[u8], page_node: &'a lopdf::Dictionary, doc: &'a lopdf::Document) -> Result<&'a lopdf::Object, lopdf::Error> {
            if let Some(obj) = page_node.get(key).ok() {
                Ok(obj)
            } else {
                let page_tree = page_node
                    .get(b"Parent")
                    .and_then(lopdf::Object::as_reference)
                    .and_then(|id| doc.get_dictionary(id))?;
                get_key(key, page_tree, doc)
            }
        }

        if let Ok(page) = self.inner_doc.get_dictionary(page_id) {
            get_key(key, page, &self.inner_doc)
        } else {
            Err(lopdf::Error::ObjectNotFound)
        }
    }
}

impl DocumentPage<'_> {
    pub fn resources(&mut self, resources_oid: Option<lopdf::ObjectId>) -> &mut lopdf::Dictionary {
        match resources_oid {
            Some(oid) => self.doc.new_objects.get_mut(&oid).unwrap(),
            None => self.page.get_mut(b"Resources").unwrap()
        }.as_dict_mut().unwrap()
    }

    pub fn setup<R, F: FnOnce(&mut InnerDocumentPage) -> R>(mut self, f: F) -> Result<R, lopdf::Error> {
        let font_id = self.doc.create_or_get_font_id();
        let mut resources_oid = None;

        if self.page.has(b"Resources") {
            let r = self.page.get_mut(b"Resources").unwrap();
            if let Ok(r) = r.as_reference() {
                let o = self.doc.inner_doc.get_object(r)?.clone();
                self.doc.new_objects.insert(r, o);
                resources_oid = Some(r);
            }
        } else {
            self.page.set("Resources", dictionary!());
        }

        self.doc.max_id += 1;
        let oid = (self.doc.max_id, 0);
        let page_fonts = match self.resources(resources_oid).get_mut(b"Font") {
            Err(_) => {
                self.resources(resources_oid).set("Font", lopdf::Object::Reference(oid));
                self.doc.new_objects.insert(oid, dictionary!().into());
                self.doc.new_objects.get_mut(&oid).unwrap().as_dict_mut().unwrap()
            }
            Ok(lopdf::Object::Reference(oid)) => {
                let oid = *oid;
                let o = self.doc.inner_doc.get_object(oid).unwrap().clone();
                self.doc.new_objects.insert(oid, o);
                self.doc.new_objects.get_mut(&oid).unwrap().as_dict_mut().unwrap()
            }
            Ok(lopdf::Object::Dictionary(d)) => d,
            _ => unimplemented!()
        };

        if !page_fonts.has(b"F_as207690_esign_Helvetica") {
            page_fonts.set("F_as207690_esign_Helvetica", font_id);
        }

        let mut inner = InnerDocumentPage {
            resources_oid,
            inner_content: self.inner_content,
            page: &mut self.page,
            page_id: self.page_id,
            doc: self.doc,
        };
        let res = f(&mut inner);

        inner.doc.max_id += 1;
        let pcid = (inner.doc.max_id, 0);
        inner.doc.new_objects.insert(
            pcid,
            lopdf::Object::Stream(
                lopdf::Stream::new(
                    lopdf::dictionary!(),
                    inner.inner_content.encode()?
                )
            ),
        );
        inner.page.set("Contents", lopdf::Object::Reference(pcid));
        inner.doc.new_objects.insert(inner.page_id, self.page.into());

        Ok(res)
    }
}

impl InnerDocumentPage<'_, '_> {
    pub fn resources(&mut self) -> &mut lopdf::Dictionary {
        match self.resources_oid {
            Some(oid) => self.doc.new_objects.get_mut(&oid).unwrap(),
            None => self.page.get_mut(b"Resources").unwrap()
        }.as_dict_mut().unwrap()
    }

    fn get_media_box(&self) -> Result<BoundingBox, lopdf::Error> {
        let media_box = self.doc.get_inherited_attr(b"MediaBox", self.page_id)?.as_array()?;
        if media_box.len() != 4 {
            return Err(lopdf::Error::Syntax(format!("Expected MediaBox to have 4 elements, actually had {}", media_box.len())));
        }

        let media_box = media_box.into_iter().map(|c| {
            c.as_f64().ok().or(c.as_i64().ok().map(|i| i as f64))
        }).collect::<Option<Vec<_>>>().ok_or(lopdf::Error::Syntax("Invalid floating point value".to_string()))?;

        let c1 = (*media_box.get(0).unwrap(), *media_box.get(1).unwrap());
        let c2 = (*media_box.get(2).unwrap(), *media_box.get(3).unwrap());

        let ll = (c1.0.min(c2.0), c1.1.min(c2.1));
        let ur = (c1.0.max(c2.0), c2.1.max(c2.1));

        Ok(BoundingBox {
            ll,
            ur,
        })
    }

    fn convert_to_pdf_space(&self, top: f64, left: f64, width: f64, height: f64) -> Result<PDFSpacePos, lopdf::Error> {
        let media_box = self.get_media_box()?;

        let page_height = media_box.ur.1 - media_box.ll.1;
        let page_width = media_box.ur.0 - media_box.ll.0;

        let h = page_height * height;
        let w = page_width * width;
        let x = media_box.ll.0 + (left * page_width);
        let y = media_box.ll.1 + (media_box.ur.1 - (top * page_height)) - h;

        Ok(PDFSpacePos {
            x,
            y,
            w,
            h,
        })
    }

    fn add_xobject<N: Into<Vec<u8>>>(&mut self, xobject_name: N, xobject_id: lopdf::ObjectId) -> Result<(), lopdf::Error> {
        let resources = self.resources();
        if !resources.has(b"XObject") {
            resources.set("XObject", lopdf::Dictionary::new());
        }
        let xobjects = resources
            .get_mut(b"XObject")
            .and_then(lopdf::Object::as_dict_mut)?;
        xobjects.set(xobject_name, lopdf::Object::Reference(xobject_id));
        Ok(())
    }

    pub fn add_text(&mut self, text: &str, top: f64, left: f64, width: f64, height: f64) -> Result<(), lopdf::Error> {
        let pos = self.convert_to_pdf_space(top, left, width, height)?;

        self.inner_content.operations.extend(vec![
            lopdf::content::Operation::new("BT", vec![]),
            lopdf::content::Operation::new("Tf", vec!["F_as207690_esign_Helvetica".into(), pos.h.into()]),
            lopdf::content::Operation::new("Td", vec![pos.x.into(), pos.y.into()]),
            lopdf::content::Operation::new("Tj", vec![lopdf::Object::string_literal(text)]),
            lopdf::content::Operation::new("ET", vec![]),
        ]);

        Ok(())
    }

    pub fn add_png_img(&mut self, img_obj_id: lopdf::ObjectId, top: f64, left: f64, width: f64, height: f64) -> Result<(), lopdf::Error> {
        let pos = self.convert_to_pdf_space(top, left, width, height)?;

        let img_name = format!("X{}", uuid::Uuid::new_v4());
        self.add_xobject(img_name.clone(), img_obj_id)?;

        self.inner_content.operations.extend(vec![
            lopdf::content::Operation::new("q", vec![]),
            lopdf::content::Operation::new(
                "cm",
                vec![pos.w.into(), 0.into(), 0.into(), pos.h.into(), pos.x.into(), pos.y.into()],
            ),
            lopdf::content::Operation::new("Do", vec![img_name.into()]),
            lopdf::content::Operation::new("Q", vec![]),
        ]);

        Ok(())
    }

    pub fn setup_signature(&mut self, sig_info: &SigningInfo) -> Result<lopdf::ObjectId, lopdf::Error> {
        let pos = self.convert_to_pdf_space(sig_info.top, sig_info.left, sig_info.width, sig_info.height)?;

        self.doc.max_id += 1;
        let sid = (self.doc.max_id, 0);
        self.doc.max_id += 1;
        let slid = (self.doc.max_id, 0);
        self.doc.max_id += 1;
        let dsid = (self.doc.max_id, 0);
        self.doc.max_id += 1;
        let xoid = (self.doc.max_id, 0);

        let acro_form = self.doc.acro_form()?;

        acro_form.set("SigFlags", lopdf::Object::Integer(3));

        let acro_fields = if acro_form.has(b"Fields") {
            acro_form.get_mut(b"Fields").unwrap().as_array_mut().unwrap()
        } else {
            acro_form.set("Fields", lopdf::Object::Array(vec![]));
            acro_form.get_mut(b"Fields").unwrap().as_array_mut().unwrap()
        };

        acro_fields.push(lopdf::Object::Reference(sid));

        self.doc.new_objects.insert(sid, dictionary! {
            "FT" => "Sig",
            "Type" => "Annot",
            "Subtype" => "Widget",
            "Rect" => lopdf::Object::Array(vec![pos.x.into(), pos.y.into(), (pos.x + pos.w).into(), (pos.h + pos.y).into()]),
            "F" => 132u32,
            // "Lock" => lopdf::Object::Reference(slid),
            "V" => lopdf::Object::Reference(dsid),
            "T" => lopdf::Object::String(format!("Signature{}", uuid::Uuid::new_v4()).into(), lopdf::StringFormat::Literal),
            "P" => lopdf::Object::Reference(self.page_id),
            "AP" => dictionary! {
                "N" => lopdf::Object::Reference(xoid)
            }
        }.into());
        self.doc.new_objects.insert(slid, dictionary! {
            "Type" => "SigFieldLock",
            "Action" => "All"
        }.into());

        let mut sig_dict = dictionary! {
            "Type" => "Sig",
            "Filter" => "Adobe.PPKLite",
            "SubFilter" => "ETSI.CAdES.detached",
            "Contents" => lopdf::Object::String(vec![0; 8192], lopdf::StringFormat::Hexadecimal),
            "ByteRange" => lopdf::Object::String(vec![0; 17], lopdf::StringFormat::Hexadecimal),
            "M" => lopdf::Object::String(
                sig_info.date.unwrap_or_else(|| chrono::Utc::now()).naive_utc().format("D:%Y%m%d%H%M%SZ").to_string().into_bytes(),
                lopdf::StringFormat::Literal
            ),
            "Reason" => lopdf::Object::String(
                sig_info.reason.as_deref().unwrap_or("Signed with AS207960 eSign").into(),
                lopdf::StringFormat::Literal
            )
        };
        if let Some(name) = &sig_info.name {
            sig_dict.set("Name", lopdf::Object::String(name.as_bytes().to_vec(), lopdf::StringFormat::Literal));
        }
        if let Some(loc) = &sig_info.location {
            sig_dict.set("Location", lopdf::Object::String(loc.as_bytes().to_vec(), lopdf::StringFormat::Literal));
        }
        if let Some(contact_info) = &sig_info.contact_info {
            sig_dict.set("ContactInfo", lopdf::Object::String(contact_info.as_bytes().to_vec(), lopdf::StringFormat::Literal));
        }
        self.doc.new_objects.insert(dsid, sig_dict.into());

        let img_name = format!("X{}", uuid::Uuid::new_v4());
        let xobject_commands = lopdf::content::Content {
            operations: vec![
                lopdf::content::Operation::new("q", vec![]),
                lopdf::content::Operation::new(
                    "cm",
                    vec![pos.w.into(), 0.into(), 0.into(), pos.h.into(), 0.into(), 0.into()],
                ),
                lopdf::content::Operation::new("Do", vec![img_name.clone().into()]),
                lopdf::content::Operation::new("Q", vec![]),
            ]
        }.encode().unwrap();
        let xobject = lopdf::Stream::new(dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "BBox" => lopdf::Object::Array(vec![0.0f64.into(), 0.0f64.into(), pos.w.into(), pos.h.into()]),
            "FormType" => 1,
            "Resources" => dictionary! {
                "ProcSet" => lopdf::Object::Array(vec![lopdf::Object::Name(b"PDF".to_vec()), lopdf::Object::Name(b"Text".to_vec())]),
                "Font" => dictionary! {
                    "F_as207690_esign_Helvetica_xobj" => dictionary! {
                        "Type" => "Font",
                        "Subtype" => "Type1",
                        "BaseFont" => "Helvetica"
                    }
                },
                "XObject" => dictionary! {
                    img_name => sig_info.img_obj_id
                }
            },
        }, xobject_commands);
        self.doc.new_objects.insert(xoid, xobject.into());

        let page_1_annotations = if self.page.has(b"Annots") {
            let r = self.page.get_mut(b"Annots").unwrap();
            if let Ok(r) = r.as_reference() {
                let o = self.doc.inner_doc.get_object(r).unwrap().clone();
                self.doc.new_objects.insert(r, o);
                self.doc.new_objects.get_mut(&r).unwrap()
            } else {
                r
            }
        } else {
            self.page.set("Annots", lopdf::Object::Array(vec![]));
            self.page.get_mut(b"Annots").unwrap()
        }.as_array_mut().unwrap();

        page_1_annotations.push(lopdf::Object::Reference(sid));

        Ok(dsid)
    }
}
