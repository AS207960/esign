function PDFViewer(url, pageAnnotations, futurePageAnnotations) {
    this.pdfjsLib = window['pdfjs-dist/build/pdf'];
    this.pdfjsLib.GlobalWorkerOptions.workerSrc = '/static/js/pdf.worker.js';
    this.pageAnnotations = pageAnnotations;
    this.futurePageAnnotations = futurePageAnnotations;
    this.loadingTask = this.pdfjsLib.getDocument(url);
    this.pages = [];
    this.pagesElms = [];
    this.signatureModal = null;
}

PDFViewer.prototype.render = function () {
    var self = this;

    return new Promise(function (resolve, reject) {
        self.loadingTask.promise.then(function (pdf) {
            console.log('PDF loaded');

            var pagePromises = [];

            for (var p = 1; p <= pdf.numPages; p++) {
                var pagePromise = pdf.getPage(p).then(function (page) {
                    console.log(`Page ${page.pageNumber} loaded`);

                    var viewport = page.getViewport({scale: 1});

                    var pagesElm = document.createElement("div");
                    pagesElm.className = "pdf-page";
                    pagesElm.style.order = page.pageNumber;
                    var pageInnerDiv = document.createElement("div");
                    pageInnerDiv.className = "pdf-page-inner";
                    pagesElm.appendChild(pageInnerDiv);

                    var canvas = document.createElement("canvas");
                    pageInnerDiv.appendChild(canvas);
                    var context = canvas.getContext('2d');

                    var pageNumSpan = document.createElement("span");
                    pageNumSpan.innerText = `Page ${page.pageNumber} of ${pdf.numPages}`;
                    pagesElm.appendChild(pageNumSpan);

                    var annotations = [];
                    var annotationsDiv = document.createElement("div");
                    annotationsDiv.className = "annotations";

                    var pdfAnnotationsDiv = document.createElement("div");
                    pdfAnnotationsDiv.className = "pdf-annotations";

                    if (self.pageAnnotations[page.pageNumber]) {
                        for (var annotation of self.pageAnnotations[page.pageNumber]) {
                            var annotationObj = {
                                id: annotation.id,
                                type: annotation.type,
                                elm: null,
                                top: annotation.top,
                                left: annotation.left,
                                width: annotation.width,
                                height: annotation.height,
                                required: true,
                                future: false,
                                signatureData: null,
                            };
                            if (annotation.type === "text") {
                                var annotationElm = document.createElement("input");
                                annotationElm.type = "text";
                                annotationElm.required = annotation.required;
                                annotationElm.name = annotation.id;
                                annotationElm.id = annotation.id;
                            } else if (annotation.type === "date") {
                                var annotationElm = document.createElement("input");
                                annotationElm.type = "date";
                                annotationElm.required = annotation.required;
                                annotationElm.name = annotation.id;
                                annotationElm.id = annotation.id;
                                if (annotation.required) {
                                    annotationElm.valueAsDate = new Date();
                                }
                            } else if (annotation.type === "checkbox") {
                                var annotationElm = document.createElement("input");
                                annotationElm.type = "checkbox";
                                annotationElm.required = annotation.required;
                                annotationElm.name = annotation.id;
                                annotationElm.id = annotation.id;
                            } else if (annotation.type === "signature") {
                                var annotationElm = document.createElement("button");
                                annotationElm.type = "button";
                                annotationElm.innerText = "Click to sign";
                                annotationElm.name = annotation.id;
                                annotationElm.id = annotation.id;
                                (function (width, height, elm) {
                                    annotationElm.addEventListener('click', function () {
                                        self.collectSignature(width, height, elm)
                                    });
                                })(viewport.width * annotation.width, viewport.height * annotation.height, annotationObj);
                            }
                            annotationObj.elm = annotationElm;
                            annotations.push(annotationObj);
                            annotationsDiv.appendChild(annotationElm);
                        }
                    }

                    for (var otherRecipientNum = 0; otherRecipientNum < self.futurePageAnnotations.length; otherRecipientNum++) {
                        var otherRecipient = self.futurePageAnnotations[otherRecipientNum];
                        if (otherRecipient[page.pageNumber]) {
                            for (var annotation of otherRecipient[page.pageNumber]) {
                                var annotationElm = document.createElement("span");
                                annotationElm.className = "future";
                                annotationElm.innerText = `For recipient ${otherRecipientNum + 1}`;
                                annotations.push({
                                    id: annotation.id,
                                    elm: annotationElm,
                                    top: annotation.top,
                                    left: annotation.left,
                                    width: annotation.width,
                                    height: annotation.height,
                                    required: false,
                                    future: true
                                });
                                annotationsDiv.appendChild(annotationElm);
                            }
                        }
                    }

                    pageInnerDiv.appendChild(pdfAnnotationsDiv);
                    pageInnerDiv.appendChild(annotationsDiv);
                    self.pagesElms.push(pagesElm);

                    self.pages.push({
                        page: page,
                        viewport: viewport,
                        canvas: canvas,
                        ctx: context,
                        annotations: annotations,
                        pdfAnnotationsDiv: pdfAnnotationsDiv,
                    });
                });
                pagePromises.push(pagePromise);
            }

            Promise.all(pagePromises).then(function () {
                resolve();
            });
        }, function (reason) {
            console.error(reason);
            reject(reason);
        });
    });
}

PDFViewer.prototype.mount = function (pdfContainer, signatureModal) {
    this.signatureModal = signatureModal;

    for (var pageElm of this.pagesElms) {
        pdfContainer.appendChild(pageElm);
    }

    var renders = {};
    var self = this;
    var promises = [];

    function renderPages() {
        for (var page of self.pages) {
            var pageNum = page.page.pageNumber;
            var outputScale = 1500 / page.viewport.width;
            var outputScale2 = pdfContainer.clientWidth / page.viewport.width;
            page.canvas.height = outputScale * page.viewport.height;
            page.canvas.width = 1500;

            var renderContext = {
                canvasContext: page.ctx,
                viewport: page.viewport,
                transform: [outputScale, 0, 0, outputScale, 0, 0],
            };
            page.ctx.clearRect(0, 0, page.canvas.width, page.canvas.height);
            if (renders[pageNum]) {
                renders[pageNum].cancel();
                renders[pageNum] = null;
            }

            var renderTask = page.page.render(renderContext);
            renders[pageNum] = renderTask;

            (function (page, outputScale2) {
                page.page.getAnnotations().then(function (annotations) {
                    page.pdfAnnotationsDiv.innerHTML = "";
                    console.log(annotations);
                    for (var annotation of annotations) {
                        if (annotation.subtype === "FreeText") {
                            console.log(annotation, page.viewport);
                            var height = annotation.rect[3] - annotation.rect[1];
                            var fontSize = Math.min(height * outputScale2 * 0.7, 14)
                            var annotationElm = document.createElement("span");
                            annotationElm.innerText = annotation.contents;
                            annotationElm.style.fontSize = `${fontSize}px`;
                            annotationElm.style.top = `${(page.viewport.height - annotation.rect[3]) * outputScale2}px`;
                            annotationElm.style.left = `${annotation.rect[0] * outputScale2}px`;
                            annotationElm.style.height = `${height * outputScale2}px`;
                            console.log((annotation.rect[2] - annotation.rect[0]) * outputScale2);
                            annotationElm.style.width = `${(annotation.rect[2] - annotation.rect[0]) * outputScale2}px`;
                            page.pdfAnnotationsDiv.appendChild(annotationElm);
                        }
                    }
                });
            })(page, outputScale2);

            for (var annotation of page.annotations) {
                var fontSize = Math.min(page.viewport.height * annotation.height * outputScale2 * 0.7, 14)
                annotation.elm.style.top = `${page.viewport.height * annotation.top * outputScale2}px`;
                annotation.elm.style.left = `${page.viewport.width * annotation.left * outputScale2}px`;
                annotation.elm.style.height = `${page.viewport.height * annotation.height * outputScale2}px`;
                annotation.elm.style.width = `${page.viewport.width * annotation.width * outputScale2}px`;
                annotation.elm.style.fontSize = `${fontSize}px`;
            }

            (function (pageNum) {
                promises.push(renderTask.promise.then(function () {
                    console.log(`Page ${pageNum} rendered`);
                }, function () {}));
            })(pageNum);
        }
    }

    const resizeObserver = new ResizeObserver(function () {
        renderPages();
    });
    resizeObserver.observe(pdfContainer);

    return new Promise(function (resolve) {
        Promise.all(promises).then(function () {
            resolve();
        });
    })
}

PDFViewer.prototype.collectSignature = function (width, height, elm) {
    this.signatureModal.collectSignature(width, height).then(function (data) {
        var imgDiv = document.createElement("div");
        imgDiv.style.top = elm.elm.style.top;
        imgDiv.style.left = elm.elm.style.left;
        imgDiv.style.width = elm.elm.style.width;
        imgDiv.style.height = elm.elm.style.height;
        imgDiv.className = "sig-img";

        var img = document.createElement("img");
        img.src = `data:image/png;base64,${data}`;
        img.style.width = "100%";
        imgDiv.appendChild(img);

        var close = document.createElement("span");
        close.innerText = "×";
        imgDiv.appendChild(close);

        close.addEventListener('click', function () {
            elm.elm.replaceWith(elm.oldElm);
            elm.elm = elm.oldElm;
            elm.signatureData = null;
        });

        elm.oldElm = elm.elm;
        elm.signatureData = data;
        elm.elm.replaceWith(imgDiv);
        elm.elm = imgDiv;
    }, function () {
    });
}

PDFViewer.prototype.canSubmit = function () {
    if (!this.pages) {
        return null;
    }

    var out = {};

    for (var page of this.pages) {
        for (var annotation of page.annotations) {
            if (!annotation.future) {
                if (annotation.type === "signature") {
                    if (!annotation.signatureData) {
                        return null;
                    }
                    out[annotation.id] = annotation.signatureData;
                } else if (annotation.type === "checkbox") {
                    if (!annotation.elm.checkValidity()) {
                        return null;
                    }
                    out[annotation.id] = annotation.elm.checked ? "✓" : "✗";
                } else {
                    if (!annotation.elm.checkValidity()) {
                        return null;
                    }
                    out[annotation.id] = annotation.elm.value;
                }
            }
        }
    }

    return out;
}

function SignerModal(modalElm) {
    this.modalElm = modalElm;
    this.modal = new bootstrap.Modal(this.modalElm, {
        show: false
    });
    this.ratio = 1;
    this.typeTab = this.modalElm.getElementsByClassName("signatureType")[0];
    this.typeTabBtn = this.modalElm.getElementsByClassName("signatureTypeBtn")[0];
    this.drawTab = this.modalElm.getElementsByClassName("signatureDraw")[0];
    this.drawTabBtn = this.modalElm.getElementsByClassName("signatureDrawBtn")[0];
    this.drawResetBtn = this.modalElm.getElementsByClassName("signatureDrawResetBtn")[0];
    this.uploadTab = this.modalElm.getElementsByClassName("signatureUpload")[0];
    this.uploadDrop = this.modalElm.getElementsByClassName("signatureUploadDrop")[0];
    this.newUploadDrop = null;
    this.uploadFile = this.uploadDrop.getElementsByTagName("input")[0];
    this.typeInput = this.modalElm.getElementsByClassName("signatureTypeInput")[0];
    this.typeCanvas = this.modalElm.getElementsByClassName("signatureTypeCanvas")[0];
    this.drawCanvas = this.modalElm.getElementsByClassName("signatureDrawCanvas")[0];
    this.typeCanvasCtx = this.typeCanvas.getContext("2d");
    this.drawCanvasCtx = this.drawCanvas.getContext("2d");
    this.resolve = null;
    this.reject = null;
    this.drawIsIdle = true;
    this.uploadCanvas = null;

    var self = this;

    this.modalElm.addEventListener('shown.bs.modal', function () {
        self.typeCanvas.height = self.typeCanvas.clientWidth * self.ratio;
        self.typeCanvas.width = self.typeCanvas.clientWidth;
        self.typeCanvasCtx.clearRect(0, 0, self.typeCanvas.width, self.typeCanvas.height);
    });
    this.typeTabBtn.addEventListener('shown.bs.tab', function () {
        self.typeCanvas.height = self.typeCanvas.clientWidth * self.ratio;
        self.typeCanvas.width = self.typeCanvas.clientWidth;
        self.typeCanvasCtx.clearRect(0, 0, self.typeCanvas.width, self.typeCanvas.height);
    })
    this.drawTabBtn.addEventListener('shown.bs.tab', function () {
        self.drawCanvas.height = self.drawCanvas.clientWidth * self.ratio;
        self.drawCanvas.width = self.drawCanvas.clientWidth;
        self.drawCanvasCtx.clearRect(0, 0, self.drawCanvas.width, self.drawCanvas.height);
        self.hasDrawn = false;
    });

    this.modalElm.addEventListener('hidden.bs.modal', function () {
        if (self.reject) {
            self.reject();
        }
        self.uploadCanvas = null;
        if (self.newUploadDrop) {
            self.newUploadDrop.replaceWith(self.uploadDrop);
            self.newUploadDrop = null;
        }
    });

    this.typeInput.addEventListener('keyup', function () {
        self.typeCanvasCtx.clearRect(0, 0, self.typeCanvas.width, self.typeCanvas.height);
        var fontsize = 60;

        do {
            self.typeCanvasCtx.font = (fontsize--) + "px Satisfy";
        } while (self.typeCanvasCtx.measureText(self.typeInput.value).width > self.typeCanvas.width);

        self.typeCanvasCtx.textAlign = 'center';
        self.typeCanvasCtx.fillText(self.typeInput.value, self.typeCanvas.width / 2, fontsize);
    });

    this.modalElm.getElementsByClassName("btn-save")[0].addEventListener('click', this.save.bind(this));

    this.drawCanvas.addEventListener('mousedown', this.drawStart.bind(this), false);
    this.drawCanvas.addEventListener('mousemove', this.drawMove.bind(this), false);
    this.drawCanvas.addEventListener('mouseup', this.drawEnd.bind(this), false);

    this.drawCanvas.addEventListener("touchstart", function (e) {
        e.preventDefault();
        var touch = e.touches[0];
        var mouseEvent = new MouseEvent("mousedown", {
            clientX: touch.clientX,
            clientY: touch.clientY
        });
        this.drawCanvas.dispatchEvent(mouseEvent);
    }.bind(this), false);
    this.drawCanvas.addEventListener("touchend", function (e) {
        e.preventDefault();
        var mouseEvent = new MouseEvent("mouseup", {});
        this.drawCanvas.dispatchEvent(mouseEvent);
    }.bind(this), false);
    this.drawCanvas.addEventListener("touchmove", function (e) {
        e.preventDefault();
        var touch = e.touches[0];
        var mouseEvent = new MouseEvent("mousemove", {
            clientX: touch.clientX,
            clientY: touch.clientY
        });
        this.drawCanvas.dispatchEvent(mouseEvent);
    }.bind(this), false);

    // document.body.addEventListener("touchstart", function (e) {
    //     if (e.target === self.drawCanvas) {
    //         e.preventDefault();
    //     }
    //     self.drawStart(e.touches[0]);
    // }, false);
    // document.body.addEventListener("touchend", function (e) {
    //     if (e.target === self.drawCanvas) {
    //         e.preventDefault();
    //     }
    //     self.drawEnd(e.changedTouches[0]);
    // }, false);
    // document.body.addEventListener("touchmove", function (e) {
    //     if (e.target === self.drawCanvas) {
    //         e.preventDefault();
    //     }
    //     self.drawStart(e.touches[0]);
    // }, false);

    this.drawResetBtn.addEventListener('click', function () {
        self.hasDrawn = false;
        self.drawCanvasCtx.clearRect(0, 0, self.drawCanvas.width, self.drawCanvas.height);
    });

    this.uploadDrop.addEventListener('dragover', this.dragOver.bind(this));
    this.uploadDrop.addEventListener('dragleave', this.dragLeave.bind(this));
    this.uploadDrop.addEventListener('drop', this.drop.bind(this));
    this.uploadFile.addEventListener('change', this.fileChange.bind(this));
}

SignerModal.prototype.collectSignature = function (width, height) {
    var self = this;
    return new Promise(function (resolve, reject) {
        self.resolve = resolve;
        self.reject = reject;
        self.ratio = height / width;
        self.hasDrawn = false;
        self.modal.show();
        self.typeInput.value = "";
    });
}

SignerModal.prototype.activeTab = function () {
    if (this.typeTab.classList.contains("active")) {
        return "type";
    } else if (this.drawTab.classList.contains("active")) {
        return "draw";
    } else if (this.uploadTab.classList.contains("active")) {
        return "upload";
    }
}

SignerModal.prototype.save = function () {
    if (this.resolve) {
        var activeTab = this.activeTab();
        if (activeTab === "type") {
            if (this.typeInput.value.length >= 1) {
                this.reject = null;
                this.modal.hide();
                this.resolve(this.typeCanvas.toDataURL("image/png").split(';base64,')[1])
            }
        } else if (activeTab === "draw") {
            if (this.hasDrawn) {
                this.reject = null;
                this.modal.hide();
                this.resolve(this.drawCanvas.toDataURL("image/png").split(';base64,')[1])
            }
        } else if (activeTab === "upload") {
            if (this.uploadCanvas) {
                this.resolve(this.uploadCanvas.toDataURL("image/png").split(';base64,')[1]);
                this.modal.hide();
            }
        }
    }
}

SignerModal.prototype.drawStart = function (event) {
    var rect = this.drawCanvas.getBoundingClientRect();
    this.drawCanvasCtx.beginPath();
    this.drawCanvasCtx.moveTo(event.clientX - rect.left, event.clientY - rect.top);
    this.drawCanvasCtx.lineWidth = 2;
    this.drawCanvasCtx.strokeStyle = '#000';
    this.drawCanvasCtx.stroke();
    this.drawIsIdle = false;
}

SignerModal.prototype.drawMove = function (event) {
    if (this.drawIsIdle) return;

    var rect = this.drawCanvas.getBoundingClientRect();
    this.drawCanvasCtx.lineTo(event.clientX - rect.left, event.clientY - rect.top);
    this.drawCanvasCtx.stroke();
}

SignerModal.prototype.drawEnd = function (event) {
    if (this.drawIsIdle) return;
    this.drawIsIdle = true;
    this.hasDrawn = true;
}

SignerModal.prototype.validDrag = function (event) {
    return event.dataTransfer.types.includes("Files") &&
        event.dataTransfer.items.length === 1 &&
        event.dataTransfer.items[0].type.startsWith("image/");
}

SignerModal.prototype.dragOver = function (event) {
    event.preventDefault();
    if (this.validDrag(event)) {
        this.uploadDrop.style.borderColor = 'green';
    } else {
        this.uploadDrop.style.borderColor = 'red';
    }
}

SignerModal.prototype.dragLeave = function (event) {
    this.uploadDrop.style.borderColor = null;
}

SignerModal.prototype.drop = function (event) {
    event.preventDefault();
    if (this.validDrag(event)) {
        this.handleUploadFile(event.dataTransfer.files.item(0));
    }
}

SignerModal.prototype.fileChange = function (event) {
    event.preventDefault();

    if (event.target.files.length !== 1) {
        this.uploadDrop.style.borderColor = 'red';
    } else {
        this.handleUploadFile(event.target.files.item(0));
    }
}

SignerModal.prototype.handleUploadFile = function (data) {
    var reader = new FileReader();
    var self = this;

    reader.addEventListener("load", function () {
        var uploadDiv = document.createElement("div");

        var resetBtn = document.createElement("button");
        resetBtn.type = "button";
        resetBtn.className = "btn btn-primary";
        resetBtn.innerText = "Reset";
        resetBtn.addEventListener('click', function () {
            self.uploadCanvas = null;
            if (self.newUploadDrop) {
                self.newUploadDrop.replaceWith(self.uploadDrop);
                self.newUploadDrop = null;
            }
        });
        uploadDiv.appendChild(resetBtn);

        var uploadCanvas = document.createElement("canvas");
        uploadDiv.appendChild(uploadCanvas);
        uploadCanvas.width = self.uploadDrop.clientWidth
        uploadCanvas.height = self.uploadDrop.clientWidth * self.ratio;

        var img = new Image();
        img.src = reader.result;

        img.addEventListener('load', function () {
            var vScale = uploadCanvas.height / img.height;
            var hScale = uploadCanvas.width / img.width;
            var scale = Math.min(vScale, hScale);
            var finalWidth = img.width * scale;
            var finalHeight = img.height * scale;
            var top = uploadCanvas.height / 2 - finalHeight / 2;
            var left = uploadCanvas.width / 2 - finalWidth / 2;

            var ctx = uploadCanvas.getContext("2d");
            ctx.fillStyle = "#fff";
            ctx.fillRect(0, 0, uploadCanvas.width, uploadCanvas.height);
            ctx.drawImage(img, left, top, finalWidth, finalHeight);

            var imageData = ctx.getImageData(0, 0, uploadCanvas.width, uploadCanvas.height);

            var min = 255;
            var max = 0;
            for (var i = 0; i < imageData.data.length; i += 4) {
                if (imageData[i + 3] === 0) {
                    imageData.data[i] = 255;
                    imageData.data[i + 1] = 255;
                    imageData.data[i + 2] = 255;
                    imageData.data[i + 3] = 255;
                } else {
                    var avg = (imageData.data[i] * 0.3 + imageData.data[i + 1] * 0.6 + imageData.data[i + 2] * 0.11);

                    imageData.data[i] = avg;
                    imageData.data[i + 1] = avg;
                    imageData.data[i + 2] = avg;
                    imageData.data[i + 3] = 255;

                    if (avg > max) {
                        max = avg;
                    }
                    if (avg < min) {
                        min = avg;
                    }
                }
            }

            var thresh = (min + max) / 2;
            console.log(thresh);
            for (var i = 0; i < imageData.data.length; i += 4) {
                if (imageData.data[i] >= thresh) {
                    imageData.data[i + 3] = 0;
                } else {
                    imageData.data[i + 3] = 255;
                }
                imageData.data[i] = 0;
                imageData.data[i + 1] = 0;
                imageData.data[i + 2] = 0;
            }
            ctx.putImageData(imageData, 0, 0);

            self.uploadDrop.replaceWith(uploadDiv);
            self.newUploadDrop = uploadDiv;
            self.uploadCanvas = uploadCanvas;
        });
    }, false);

    reader.readAsDataURL(data);
}