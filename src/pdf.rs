use std::io::Write;

pub struct Document {
    inner_doc: lopdf::Document,
    font_id: Option<lopdf::ObjectId>,
    pages: std::collections::BTreeMap<u32, lopdf::ObjectId>,
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
    inner_content: lopdf::content::Content,
    doc: &'a mut Document,
}

impl Document {
    pub fn new(doc: lopdf::Document) -> Self {
        Self {
            pages: doc.get_pages(),
            inner_doc: doc,
            font_id: None,
        }
    }

    pub fn finalise(mut self) -> lopdf::Document {
        self.inner_doc.prune_objects();
        self.inner_doc
    }

    pub fn page(&mut self, page: u32) -> Result<DocumentPage, lopdf::Error> {
        let page_id = match self.pages.get(&page).map(|o| *o) {
            Some(i) => i,
            None => return Err(lopdf::Error::PageNumberNotFound(page))
        };

        Ok(DocumentPage {
            inner_content: self.inner_doc.get_and_decode_page_content(page_id)?,
            doc: self,
            page_id,
        })
    }

    fn create_or_get_font_id(&mut self) -> lopdf::ObjectId {
        match self.font_id {
            Some(f) => f,
            None => {
                let font_id = self.inner_doc.add_object(dictionary! {
                    "Type" => "Font",
                    "Subtype" => "Type1",
                    "BaseFont" => "Helvetica",
                });
                self.font_id = Some(font_id);
                font_id
            }
        }
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

    fn resources(&mut self) -> Result<&mut lopdf::Dictionary, lopdf::Error> {
        self.doc.inner_doc.get_or_create_resources(self.page_id).and_then(lopdf::Object::as_dict_mut)
    }

    pub fn setup(&mut self) -> Result<(), lopdf::Error> {
        let font_id = self.doc.create_or_get_font_id();
        let page_fonts = match self.resources()?.get_mut(b"Font") {
            Err(_) => {
                let oid = self.doc.inner_doc.add_object(dictionary!());
                self.resources()?.set("Font", lopdf::Object::Reference(oid));
                self.doc.inner_doc.get_object_mut(oid).and_then(lopdf::Object::as_dict_mut)?
            }
            Ok(lopdf::Object::Reference(oid)) => {
                let oid = *oid;
                self.doc.inner_doc.get_object_mut(oid).and_then(lopdf::Object::as_dict_mut)?
            }
            Ok(lopdf::Object::Dictionary(d)) => d,
            _ => unimplemented!()
        };

        if !page_fonts.has(b"F_as207690_esign_Helvetica") {
            page_fonts.set("F_as207690_esign_Helvetica", font_id);
        }

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

    fn png_error_to_lopdf(err: png::DecodingError) -> lopdf::Error {
        match err {
            png::DecodingError::IoError(io) => lopdf::Error::IO(io),
            png::DecodingError::Format(f) => lopdf::Error::Syntax(f.to_string()),
            png::DecodingError::Parameter(f) => lopdf::Error::Syntax(f.to_string()),
            png::DecodingError::LimitsExceeded => lopdf::Error::IO(std::io::ErrorKind::OutOfMemory.into())
        }
    }

    pub fn add_png_img(&mut self, data: &[u8], top: f64, left: f64, width: f64, height: f64) -> Result<(), lopdf::Error> {
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

            let mut mask_dict = lopdf::Dictionary::new();
            mask_dict.set("Type", lopdf::Object::Name("XObject".into()));
            mask_dict.set("Subtype", lopdf::Object::Name("Image".into()));
            mask_dict.set("ColorSpace", lopdf::Object::Name("DeviceGray".into()));
            mask_dict.set("Width", lopdf::Object::Integer(img_data.width.into()));
            mask_dict.set("Height", lopdf::Object::Integer(img_data.height.into()));
            mask_dict.set("BitsPerComponent", lopdf::Object::Integer(bits_per_component));
            mask_dict.set("Filter", lopdf::Object::Array(vec!["ASCIIHexDecode".into(), "FlateDecode".into()]));
            let mask_obj = lopdf::Stream::new(mask_dict, mask_hex_data.into())
                .with_compression(false);
            self.doc.inner_doc.add_object(mask_obj)
        });

        let mut img_dict = lopdf::Dictionary::new();
        img_dict.set("Type", lopdf::Object::Name("XObject".into()));
        img_dict.set("Subtype", lopdf::Object::Name("Image".into()));
        img_dict.set("ColorSpace", lopdf::Object::Name(img_bytes_format.into()));
        img_dict.set("Width", lopdf::Object::Integer(img_data.width.into()));
        img_dict.set("Height", lopdf::Object::Integer(img_data.height.into()));
        img_dict.set("BitsPerComponent", lopdf::Object::Integer(bits_per_component));
        img_dict.set("Filter", lopdf::Object::Array(vec!["ASCIIHexDecode".into(), "FlateDecode".into()]));
        if let Some(mask_obj_id) = mask_obj_id {
            img_dict.set("SMask", lopdf::Object::Reference(mask_obj_id.into()));
        }
        let img_obj = lopdf::Stream::new(img_dict, img_hex_data.into())
            .with_compression(false);
        let img_obj_id = self.doc.inner_doc.add_object(img_obj);

        let pos = self.convert_to_pdf_space(top, left, width, height)?;

        let img_name = format!("X{}", uuid::Uuid::new_v4());
        self.doc.inner_doc.add_xobject(self.page_id, img_name.clone(), img_obj_id)?;

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

    pub fn done(self) -> Result<(), lopdf::Error> {
        self.doc.inner_doc.change_page_content(self.page_id, self.inner_content.encode()?)?;
        Ok(())
    }
}