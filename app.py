
import uuid
from io import BytesIO
from datetime import datetime
import pytz
import streamlit as st
import os

from utils import sanitize_text, parse_datetime_es, format_datetime_es, make_safe_filename
from xsig_pdf import render_pdf_from_xsig

st.set_page_config(page_title="XSIG → PDF", page_icon="🧾", layout="centered")

logo_path = os.path.join(os.path.dirname(__file__), "logo-hacienda.png")

col1, col2 = st.columns([1, 4])
with col1:
    st.image(logo_path, width=80)  # Ajusta el tamaño a tu gusto
with col2:
    st.markdown(
        "<h2 style='margin-bottom:0;'>Diputación de Sevilla</h2>",
        unsafe_allow_html=True
    )
    
st.title("XSIG → PDF (Factura electrónica a PDF)")
st.markdown(
    "Sube un archivo **XSIG/XML** de una factura electrónica, rellena los campos del **Registro Contable de Facturas** "
    "y genera un **PDF** de representación listo para descargar. Todo el procesamiento se realiza en memoria."
)

# Sidebar
with st.sidebar:
    st.header("Acerca de")
    st.caption("Versión 1.0 · Autor: Enteza-CarrySoft · Procesamiento local en memoria.")
    detailed = st.toggle("Modo detallado (logs)")

# Formulario
with st.form("form_xsig"):
    file = st.file_uploader("Sube el archivo XSIG", type=["xsig", "xml"], help="Tamaño máximo recomendado: 20 MB")
    num_registro = st.text_input("Número de Registro", placeholder="2025/000123", help="Solo letras, números, guiones, guiones bajos, barras y puntos.")
    tipo_registro = st.text_input("Punto de Entrada / Tipo de Registro", placeholder="FACe / DIR3", help="Texto libre seguro.")
    num_rcf = st.text_input("Número RCF (opcional)", placeholder="RCF-2025-000987", help="Si no aplica, puedes repetir el número de registro.")

    col1, col2 = st.columns(2)
    with col1:
        f_reg_date = st.date_input("Fecha de registro", value=datetime.now().date())
    with col2:
        f_reg_time = st.time_input("Hora de registro", value=datetime.now().time().replace(microsecond=0))

    submitted = st.form_submit_button("Generar PDF")

if submitted:
    # Validaciones básicas
    if not file:
        st.error("Debes subir un archivo XSIG/XML.")
        st.stop()

    if file.size and file.size > 20 * 1024 * 1024:
        st.error("El archivo supera el límite de 20 MB.")
        st.stop()

    try:
        num_registro_s = sanitize_text(num_registro)
        tipo_registro_s = sanitize_text(tipo_registro)
        num_rcf_s = sanitize_text(num_rcf) if num_rcf.strip() else sanitize_text(num_registro)

        # Fecha/hora en zona Europe/Madrid
        tz = pytz.timezone("Europe/Madrid")
        fecha_hora_registro_dt = tz.localize(datetime.combine(f_reg_date, f_reg_time))

        with st.spinner("Generando PDF..."):
            pdf_bytes_io = render_pdf_from_xsig(
                file,
                num_registro=num_registro_s,
                tipo_registro=tipo_registro_s,
                num_rcf=num_rcf_s,
                fecha_hora_registro=fecha_hora_registro_dt,
                timezone="Europe/Madrid",
            )

        st.success("PDF generado correctamente.")

        # Guardamos en session_state para descargar sin perder en re-renders
        st.session_state["pdf_bytes"] = pdf_bytes_io.getvalue()

        # Resumen de datos
        with st.expander("Resumen de datos utilizados", expanded=True):
            st.write({
                "num_registro": num_registro_s,
                "tipo_registro": tipo_registro_s,
                "num_rcf": num_rcf_s,
                "fecha_hora_registro": format_datetime_es(fecha_hora_registro_dt),
            })

        # Botón de descarga
        suggested_name = make_safe_filename(f"Factura_{num_rcf_s or num_registro_s}_{fecha_hora_registro_dt.strftime('%Y%m%d_%H%M')}.pdf")
        st.download_button(
            label="Descargar PDF",
            data=st.session_state["pdf_bytes"],
            file_name=suggested_name,
            mime="application/pdf"
        )

        if detailed:
            with st.expander("Detalles técnicos"):
                st.code(f"CorrID: {uuid.uuid4()}")
    except Exception as e:
        corr = uuid.uuid4()
        st.error(f"Ha ocurrido un error durante la generación del PDF. ID: {corr}")
        if detailed:
            with st.expander("Traza"):
                import traceback
                st.code(traceback.format_exc())
