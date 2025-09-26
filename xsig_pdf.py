
import io
import base64
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import BinaryIO
from dateutil import parser as date_parser

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.enums import TA_RIGHT

# ------------------------------
# Utilidades internas
# ------------------------------

def _extract_xml_from_xsig_bytes(xsig_bytes: bytes) -> bytes:
    """Extrae el bloque XML de un contenedor XSIG buscando el marcador '<?xml'."""
    xml_start = xsig_bytes.find(b"<?xml")
    xml_end = xsig_bytes.rfind(b">") + 1
    if xml_start != -1 and xml_end > xml_start:
        return xsig_bytes[xml_start:xml_end]
    # Si ya es XML puro o no se encuentra, devolvemos tal cual para intentar parseo
    return xsig_bytes

def _extract_signature_info_from_xml(xml_root: ET.Element) -> dict:
    """Extrae información de la firma electrónica si está presente en el XML."""
    try:
        ns = {
            'ds': 'http://www.w3.org/2000/09/xmldsig#',
            'xades': 'http://uri.etsi.org/01903/v1.3.2#'
        }

        cert_base64 = xml_root.findtext(".//ds:X509Certificate", default="", namespaces=ns)
        if not cert_base64:
            return {"estado": "No se encontró certificado"}

        cert_der = base64.b64decode(cert_base64)
        cert = x509.load_der_x509_certificate(cert_der, backend=default_backend())

        # Sujeto y emisor
        subject = cert.subject
        issuer = cert.issuer

        def _get_attr(name_oid, default="N/A"):
            try:
                return subject.get_attributes_for_oid(name_oid)[0].value
            except Exception:
                return default

        from cryptography.x509.oid import NameOID, ObjectIdentifier

        cn = _get_attr(NameOID.COMMON_NAME)
        try:
            nif = subject.get_attributes_for_oid(ObjectIdentifier("2.5.4.5"))[0].value
        except Exception:
            nif = "N/A"

        try:
            cert_issuer = issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            cert_issuer = "No disponible"

        try:
            algorithm = cert.signature_hash_algorithm.name.upper()
        except Exception:
            algorithm = "N/A"

        signing_time_str = xml_root.findtext(".//xades:SigningTime", default="No especificada", namespaces=ns)

        # Ventanas de validez (naive, sin tz)
        valido_desde = cert.not_valid_before
        valido_hasta = cert.not_valid_after

        # Estado actual del certificado
        now = datetime.utcnow()
        if now < valido_desde:
            estado_actual = "Certificado aún no válido (vigencia futura)"
        elif now > valido_hasta:
            estado_actual = "Certificado caducado"
        else:
            estado_actual = "Certificado actualmente válido"

        # Validez en la fecha de firma
        try:
            signing_datetime = date_parser.parse(signing_time_str)
            signing_naive = signing_datetime.replace(tzinfo=None)
            if valido_desde <= signing_naive <= valido_hasta:
                validez_en_firma = "Certificado válido en la fecha de la firma"
            else:
                validez_en_firma = "Certificado NO era válido en la fecha de la firma"
        except Exception as e:
            validez_en_firma = f"No se pudo validar la fecha de firma: {e}"

        return {
            "estado": "Firma encontrada",
            "firmante": cn,
            "nif": nif,
            "algoritmo": algorithm,
            "fecha_firma": signing_time_str,
            "valido_desde": valido_desde.strftime("%Y-%m-%d"),
            "valido_hasta": valido_hasta.strftime("%Y-%m-%d"),
            "estado_certificado": estado_actual,
            "validez_en_firma": validez_en_firma,
            "autoridad_certificadora": cert_issuer
        }
    except Exception as e:
        return {"estado": f"Error al extraer firma: {str(e)}"}

def _extract_invoice_data_from_xml(xml_root: ET.Element) -> dict:
    """Extrae datos de la factura del XML (Facturae) con tolerancia a campos ausentes."""
    seller_party = xml_root.find(".//SellerParty")
    if seller_party is not None:
        tax_id = seller_party.findtext(".//TaxIdentification/TaxIdentificationNumber", default="N/A")
        corporate_name = seller_party.findtext(".//LegalEntity/CorporateName", default="N/A")
        address = seller_party.findtext(".//LegalEntity/AddressInSpain/Address", default="N/A")
        postcode = seller_party.findtext(".//LegalEntity/AddressInSpain/PostCode", default="N/A")
        town = seller_party.findtext(".//LegalEntity/AddressInSpain/Town", default="N/A")
        province = seller_party.findtext(".//LegalEntity/AddressInSpain/Province", default="N/A")
        country = seller_party.findtext(".//LegalEntity/AddressInSpain/CountryCode", default="N/A")
        emitter_address = f"{address}, {postcode} {town}, {province}, {country}"
    else:
        tax_id = corporate_name = emitter_address = "N/A"
        town = postcode = province = "N/A"

    emitter = {
        "Nombre": corporate_name,
        "NIF": tax_id,
        "Dirección": emitter_address,
        "Poblacion": town,
        "Cod.Postal": postcode,
        "Provincia": province
    }

    invoice_additional_info = (xml_root.findtext(".//AdditionalData/InvoiceAdditionalInformation", default="") or "").strip()
    legal_references = [ref.text.strip() for ref in xml_root.findall(".//LegalLiterals/LegalReference") if ref.text and ref.text.strip() != ""]

    buyer_party = xml_root.find(".//BuyerParty")
    if buyer_party is not None:
        buyer_tax_id = buyer_party.findtext(".//TaxIdentification/TaxIdentificationNumber", default="N/A")
        buyer_name = buyer_party.findtext(".//LegalEntity/CorporateName", default="N/A")
        b_address = buyer_party.findtext(".//LegalEntity/AddressInSpain/Address", default="N/A")
        b_postcode = buyer_party.findtext(".//LegalEntity/AddressInSpain/PostCode", default="")
        b_town = buyer_party.findtext(".//LegalEntity/AddressInSpain/Town", default="")
        b_province = buyer_party.findtext(".//LegalEntity/AddressInSpain/Province", default="")
        b_country = buyer_party.findtext(".//LegalEntity/AddressInSpain/CountryCode", default="")
        buyer_address = f"{b_address}, {b_postcode} {b_town}, {b_province}, {b_country}"
    else:
        buyer_tax_id = buyer_name = buyer_address = "N/A"

    receptor = {
        "Nombre": buyer_name,
        "NIF": buyer_tax_id,
        "Dirección": buyer_address
    }

    destinos = []
    if buyer_party is not None:
        for admin in buyer_party.findall(".//AdministrativeCentres/AdministrativeCentre"):
            code = admin.findtext("CentreCode", default="N/A")
            desc = admin.findtext("Name", default="N/A")
            destinos.append(f"{code} - {desc}")
    receptor["OfiCont"] = destinos[0] if len(destinos) > 0 else "N/A"
    receptor["OrgGest"] = destinos[1] if len(destinos) > 1 else "N/A"
    receptor["UndTram"] = destinos[2] if len(destinos) > 2 else "N/A"

    invoice_element = xml_root.find(".//Invoices/Invoice")
    if invoice_element is not None:
        invoice_number = invoice_element.findtext(".//InvoiceHeader/InvoiceNumber", default="N/A")
        invoice_series = invoice_element.findtext(".//InvoiceHeader/InvoiceSeriesCode", default="")
        invoice_type = invoice_element.findtext(".//InvoiceHeader/InvoiceDocumentType", default="N/A")
        invoice_currency = invoice_element.findtext(".//InvoiceIssueData/InvoiceCurrencyCode", default="N/A")
        raw_date = invoice_element.findtext(".//InvoiceIssueData/IssueDate", default="N/A")
        invoice_class = invoice_element.findtext(".//InvoiceHeader/InvoiceClass", default="N/A")

        invoice_class_map = {
            "OO": "Original",
            "OR": "Original Rectificativa",
            "OC": "Original Recapitulativa",
            "CO": "Duplicado Original",
            "CR": "Duplicado Rectificativa",
            "CC": "Duplicado Recapitulativa"
        }
        invoice_class_desc = invoice_class_map.get(invoice_class, "N/A")

        try:
            issue_date = datetime.strptime(raw_date, "%Y-%m-%d").strftime("%d/%m/%Y")
        except Exception:
            issue_date = raw_date
        invoice_number = f"{invoice_series}{invoice_number}"
    else:
        invoice_number = issue_date = invoice_type = invoice_currency = "N/A"
        invoice_class_desc = "N/A"

    totals = {}
    if invoice_element is not None:
        invoice_totals = invoice_element.find(".//InvoiceTotals")
        if invoice_totals is not None:
            totals["TotalGrossAmount"] = invoice_totals.findtext("TotalGrossAmount", default="0.00")
            totals["TotalGeneralDiscounts"] = invoice_totals.findtext("TotalGeneralDiscounts", default="0.00")
            totals["TotalGrossAmountBeforeTaxes"] = invoice_totals.findtext("TotalGrossAmountBeforeTaxes", default="N/A")
            totals["TotalTaxOutputs"] = invoice_totals.findtext("TotalTaxOutputs", default="N/A")
            totals["TotalTaxesWithheld"] = invoice_totals.findtext("TotalTaxesWithheld", default="N/A")
            totals["InvoiceTotal"] = invoice_totals.findtext("InvoiceTotal", default="N/A")
            totals["TotalOutstandingAmount"] = invoice_totals.findtext("TotalOutstandingAmount", default="N/A")
            totals["TotalExecutableAmount"] = invoice_totals.findtext("TotalExecutableAmount", default="N/A")

    items = []
    if invoice_element is not None:
        for line in invoice_element.findall(".//Items/InvoiceLine"):
            description = line.findtext("ItemDescription", default="N/A")
            quantity = line.findtext("Quantity", default="N/A")
            unit_price = line.findtext("UnitPriceWithoutTax", default="N/A")
            total_cost = line.findtext("TotalCost", default="N/A")
            items.append({
                "Descripción": description,
                "Cantidad": quantity,
                "Precio Unitario": unit_price,
                "Importe": total_cost
            })

    firma_info = _extract_signature_info_from_xml(xml_root)
    data = {
        "Número de Factura": invoice_number,
        "Fecha": issue_date,
        "Tipo Dcomento": invoice_type,
        "Moneda": invoice_currency,
        "Clase Factura": invoice_class_desc,
        "Total Factura": totals.get("InvoiceTotal", "N/A"),
        "Totales": totals,
        "Emisor": emitter,
        "Receptor": receptor,
        "Conceptos": items,
        "Firma": firma_info,
        "InfoAdicional": invoice_additional_info,
        "ReferenciasLegales": legal_references
    }
    return data

def _add_header(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    # Mensaje opcional en cabecera (vacío por defecto)
    canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, doc.pagesize[1] - 20, "")
    canvas.restoreState()

def _add_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    text = "REPRESENTACIÓN DEL CONTENIDO DE LA FACTURA ELECTRÓNICA Y DEL REGISTRO CONTABLE DE FACTURAS."
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    canvas.drawString(doc.leftMargin, 20, text)
    canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 20, f"{timestamp}")
    canvas.restoreState()

def _generate_pdf_from_invoice(invoice: dict, parametros: dict) -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=18)
    elements = []
    styles = getSampleStyleSheet()
    styleH = styles['Heading1']
    styleN = styles['Normal']
    styleN.fontSize = 8
    styleN.leading = 10

    table_cell_style = ParagraphStyle('table_cell_style', parent=styles['Normal'], fontSize=8, leading=10)
    header_cell_style = ParagraphStyle('header_cell_style', parent=styles['Normal'], fontSize=8, leading=10, alignment=1)
    right_align_style = ParagraphStyle(name='RightAlign', parent=table_cell_style, alignment=TA_RIGHT)

    titulo = Paragraph("Factura", styleH)
    info_factura = Paragraph(
        f"<b>Fecha de Emisión:</b> {invoice.get('Fecha', 'N/A')} "
        f"<b>Número:</b> {invoice.get('Número de Factura', 'N/A')}<br/>"
        f"<b>Clase de factura:</b> {invoice.get('Clase Factura', 'N/A')} "
        f"<b>Moneda:</b> {invoice.get('Moneda', 'N/A')}", styleN
    )

    info_extra = Paragraph(
        f"<b>Num.Registro:</b> {parametros['num_registro']}<br/>"
        f"<b>Punto de Entrada:</b> {parametros['tipo_registro']}<br/>"
        f"<b>Num.Factura RCF:</b> {parametros['num_rcf']}<br/>"
        f"<b>Fecha y hora registro:</b> {parametros['fecha_hora_registro']}", styleN
    )

    table_info = Table([
        [[titulo, info_factura], info_extra]
    ], colWidths=[doc.width * 0.6, doc.width * 0.4])

    table_info.setStyle(TableStyle([
        ('BOX', (1, 0), (1, 0), 1, colors.black),
        ('INNERGRID', (1, 0), (1, 0), 0.5, colors.grey),
        ('BACKGROUND', (1, 0), (1, 0), colors.whitesmoke),
        ('VALIGN', (0, 0), (-1, -1), 'TOP')
    ]))

    elements.append(table_info)
    elements.append(Spacer(1, 12))

    emisor = invoice.get("Emisor", {})
    receptor = invoice.get("Receptor", {})
    receptor_info = (
        f"<b>Nombre:</b> {receptor.get('Nombre', 'N/A')}<br/>"
        f"<b>NIF:</b> {receptor.get('NIF', 'N/A')}<br/>"
        f"<b>Dirección:</b> {receptor.get('Dirección', 'N/A')}<br/>"
        f"<b>Ofi.Cont.:</b> {receptor.get('OfiCont', 'N/A')}<br/>"
        f"<b>Org.Gest:</b> {receptor.get('OrgGest', 'N/A')}<br/>"
        f"<b>Und.Tram:</b> {receptor.get('UndTram', 'N/A')}"
    )

    data_parties = [
        [Paragraph("<b>EMISOR</b>", styleN), Paragraph("<b>RECEPTOR</b>", styleN)],
        [Paragraph(
            f"<b>Nombre:</b> {emisor.get('Nombre', 'N/A')}<br/>"
            f"<b>NIF:</b> {emisor.get('NIF', 'N/A')}<br/>"
            f"<b>Dirección:</b> {emisor.get('Dirección', 'N/A')}<br/>"
            f"<b>Poblacion:</b> {emisor.get('Poblacion', 'N/A')}<br/>"
            f"<b>Cod.Postal:</b> {emisor.get('Cod.Postal', 'N/A')}<br/>"
            f"<b>Provincia:</b> {emisor.get('Provincia', 'N/A')}", styleN
        ),
         Paragraph(receptor_info, styleN)]
    ]

    table_parties = Table(data_parties, colWidths=[doc.width/2.0, doc.width/2.0])
    table_parties.setStyle(TableStyle([
        ('BOX', (0,0), (-1,-1), 1, colors.black),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey)
    ]))
    elements.append(table_parties)
    elements.append(Spacer(1, 12))

    items = invoice.get("Conceptos", [])
    if items:
        data_table = [[
            Paragraph("Descripción", header_cell_style),
            Paragraph("Cantidad", header_cell_style),
            Paragraph("Precio Unitario", header_cell_style),
            Paragraph("Importe", header_cell_style)
        ]]
        for item in items:
            def _fmt(val, fmt):
                try:
                    return fmt.format(float(val))
                except Exception:
                    return val if val is not None else "N/A"

            data_table.append([
                Paragraph(item.get("Descripción", "N/A"), table_cell_style),
                Paragraph(_fmt(item.get("Cantidad", 0), "{:.2f}"), right_align_style),
                Paragraph(_fmt(item.get("Precio Unitario", 0), "{:.4f}"), right_align_style),
                Paragraph(_fmt(item.get("Importe", 0), "{:.2f}"), right_align_style)
            ])

        col_widths = [doc.width * 0.60, (doc.width * 0.35) / 3, (doc.width * 0.45) / 3, (doc.width * 0.40) / 3]
        table_items = Table(data_table, colWidths=col_widths)
        table_items.setStyle(TableStyle([
            ('BOX', (0,0), (-1,-1), 1, colors.black),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('ALIGN', (1,1), (-1,-1), 'CENTER')
        ]))
        elements.append(table_items)
        elements.append(Spacer(1, 12))
    else:
        elements.append(Paragraph("No hay conceptos en la factura.", styleN))
        elements.append(Spacer(1, 12))

    totals = invoice.get("Totales", {})
    if totals:
        totals_data = [
            [Paragraph("<b>Importe bruto total:</b>", styleN), Paragraph(totals.get("TotalGrossAmount", "N/A"), right_align_style)],
            [Paragraph("<b>Descuentos generales:</b>", styleN), Paragraph(totals.get("TotalGeneralDiscounts", "N/A"), right_align_style)],
            [Paragraph("<b>Base imponible antes de impuestos:</b>", styleN), Paragraph(totals.get("TotalGrossAmountBeforeTaxes", "N/A"), right_align_style)],
            [Paragraph("<b>Importe de impuestos:</b>", styleN), Paragraph(totals.get("TotalTaxOutputs", "N/A"), right_align_style)],
            [Paragraph("<b>Retenciones:</b>", styleN), Paragraph(totals.get("TotalTaxesWithheld", "N/A"), right_align_style)],
            [Paragraph("<b>Importe total factura:</b>", styleN), Paragraph(totals.get("InvoiceTotal", "N/A"), right_align_style)]
        ]
        totals_table = Table(totals_data, colWidths=[doc.width * 0.7, doc.width * 0.3])
        totals_table.setStyle(TableStyle([
            ('BOX', (0,0), (-1,-1), 1, colors.black),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey)
        ]))
        elements.append(totals_table)
        elements.append(Spacer(1, 12))

    if invoice.get('InfoAdicional'):
        elements.append(Paragraph("<b>Información Adicional:</b>", styleN))
        elements.append(Paragraph(invoice['InfoAdicional'], styleN))
        elements.append(Spacer(1, 12))

    if invoice.get('ReferenciasLegales'):
        elements.append(Paragraph("<b>Literales Legales:</b>", styleN))
        for ref in invoice['ReferenciasLegales']:
            elements.append(Paragraph(ref, styleN))
        elements.append(Spacer(1, 12))

    # Firma electrónica (si existe)
    firma = invoice.get("Firma", {})
    if firma and firma.get("estado", "").startswith("Firma"):
        styleN.fontSize = 7
        # Reutilizamos getSampleStyleSheet importado a nivel de módulo (evitamos sombrear el nombre en ámbito local)
        style_subtitle = ParagraphStyle(name='SubtitleCentered', parent=getSampleStyleSheet()['Heading2'], alignment=1)

        elements.append(Spacer(1, 12))
        elements.append(Paragraph("Firma electrónica", style_subtitle))
        elements.append(Spacer(1, 6))

        firma_data = [
            [
                Paragraph("<b>Firmante:</b>", styleN), Paragraph(firma.get("firmante", "N/A"), styleN),
                Paragraph("<b>NIF:</b>", styleN), Paragraph(firma.get("nif", "N/A"), styleN),
                Paragraph("<b>Algoritmo:</b>", styleN), Paragraph(firma.get("algoritmo", "N/A"), styleN)
            ],
            [
                Paragraph("<b>Fecha Firma:</b>", styleN), Paragraph(firma.get("fecha_firma", "N/A"), styleN),
                Paragraph("<b>Desde:</b>", styleN), Paragraph(firma.get("valido_desde", "N/A"), styleN),
                Paragraph("<b>Hasta:</b>", styleN), Paragraph(firma.get("valido_hasta", "N/A"), styleN)
            ],
            [
                Paragraph("<b>Estado actual:</b>", styleN), Paragraph(firma.get("estado_certificado", "N/A"), styleN),
                Paragraph("<b>Validez en firma:</b>", styleN), Paragraph(firma.get("validez_en_firma", "N/A"), styleN),
                Paragraph("<b>Autoridad Certificación:</b>", styleN), Paragraph(firma.get("autoridad_certificadora", "N/A"), styleN)
            ]
        ]

        col_widths = [
            doc.width * 0.12,
            doc.width * 0.40,
            doc.width * 0.10,
            doc.width * 0.16,
            doc.width * 0.10,
            doc.width * 0.12
        ]

        table_firma = Table(firma_data, colWidths=col_widths)
        table_firma.setStyle(TableStyle([
            ('BOX', (0,0), (-1,-1), 1, colors.black),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        elements.append(table_firma)
        elements.append(Spacer(1, 12))

    doc.build(elements, onFirstPage=lambda c, d: (_add_header(c, d), _add_footer(c, d)),
                    onLaterPages=lambda c, d: (_add_header(c, d), _add_footer(c, d)))
    buffer.seek(0)
    return buffer

# ------------------------------
# API pública del módulo
# ------------------------------

def render_pdf_from_xsig(
    xsig_file: BinaryIO,
    *,
    num_registro: str,
    tipo_registro: str,
    num_rcf: str,
    fecha_hora_registro: datetime,
    timezone: str = "Europe/Madrid",
) -> io.BytesIO:
    """
    Devuelve un BytesIO con el PDF generado a partir del XSIG y los campos auxiliares.
    No escribe a disco.
    """
    xsig_bytes = xsig_file.read()
    if not xsig_bytes:
        raise ValueError("Archivo vacío o no legible.")

    xml_bytes = _extract_xml_from_xsig_bytes(xsig_bytes)
    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        raise ValueError(f"El archivo no parece un XSIG/XML válido: {e}")

    invoice_data = _extract_invoice_data_from_xml(root)

    # Incorporar metadatos adicionales
    params = {
        "num_registro": num_registro,
        "tipo_registro": tipo_registro,
        "num_rcf": num_rcf,
        "fecha_hora_registro": fecha_hora_registro.strftime("%d/%m/%Y %H:%M"),
    }

    pdf_buffer = _generate_pdf_from_invoice(invoice_data, params)
    pdf_buffer.seek(0)
    return pdf_buffer
