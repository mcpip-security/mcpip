"""Builders shared by the irs-efile-viewer tests: synthetic returns and stylesheet trees.

(Not in conftest.py: a repository-wide pytest run imports several conftest modules, so
``from conftest import ...`` could pick up the wrong one.)
"""

from __future__ import annotations

import textwrap
from pathlib import Path

GIF_1PX = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b"
)


def efile_xml(
    *,
    version: str = "2014v5.0",
    documents: str = '<IRSTEST documentId="RetDoc1"><Txt>hello</Txt></IRSTEST>',
    header: str | None = None,
) -> bytes:
    """A minimal, namespaced e-file return around ``documents``."""
    header = header or (
        "<ReturnTs>2015-05-14T18:01:56-05:00</ReturnTs><TaxPeriodBeginDt>2014-01-01</TaxPeriodBeginDt>"
        "<TaxPeriodEndDt>2014-12-31</TaxPeriodEndDt><ReturnTypeCd>990</ReturnTypeCd>"
        "<Filer><EIN>201585919</EIN><BusinessName><BusinessNameLine1Txt>EXAMPLE ORG</BusinessNameLine1Txt>"
        "</BusinessName></Filer><TaxYr>2014</TaxYr>"
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<Return xmlns="http://www.irs.gov/efile" returnVersion="{version}">'
        f'<ReturnHeader binaryAttachmentCnt="0">{header}</ReturnHeader>'
        f'<ReturnData documentCnt="1">{documents}</ReturnData></Return>'
    ).encode()


#: Stands in for IRS CommonPathRef.xsl, in the Jekyll-patched betson layout.
COMMON_PATH_REF = textwrap.dedent(
    """\
    ---
    ---
    <?xml version="1.0" encoding="UTF-8"?>
    <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
      <xsl:param name="RtnHdrData" select="/AppData/SubmissionHeaderAndDocument/ReturnHeader"/>
      <xsl:param name="RtnDoc" select="/AppData/SubmissionHeaderAndDocument/SubmissionDocument"/>
      <xsl:param name="TaxYear" select="substring(/AppData/Parameters/SubmissionVersion,1,4)"/>
      <xsl:param name="ImagePath"><xsl:value-of select="concat('{{ site.github.url }}/mef/rrprd/sdi/versioned/',$TaxYear,'/images')"/></xsl:param>
      <xsl:param name="CSSPath"><xsl:value-of select="concat('{{ site.github.url }}/mef/rrprd/sdi/versioned/',$TaxYear,'/styles')"/></xsl:param>
      <xsl:param name="ScriptPath"><xsl:value-of select="concat('{{ site.github.url }}/mef/rrprd/sdi/versioned/',$TaxYear,'/scripts')"/></xsl:param>
      <xsl:param name="NonVersionedImagePath">{{ site.github.url }}/mef/rrprd/common/images</xsl:param>
    </xsl:stylesheet>
    """
)

#: A document stylesheet exercising everything the post-processor must handle,
#: including an unsafe ``disable-output-escaping`` of filing data.
TEST_FORM = textwrap.dedent(
    """\
    <?xml version="1.0" encoding="UTF-8"?>
    <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
      <xsl:include href="CommonPathRef.xsl"/>
      <xsl:output method="html" indent="yes"/>
      <xsl:param name="Form" select="$RtnDoc/IRSTEST"/>
      <xsl:template match="/">
        <xsl:text disable-output-escaping="yes">&lt;!DOCTYPE html&gt;</xsl:text>
        <html><head><title>TY <xsl:value-of select="$TaxYear"/> Test Form</title>
          <script src="{$ScriptPath}/FormDisplay.js"></script>
          <link rel="stylesheet" type="text/css" href="{$CSSPath}/body.css"/>
          <link rel="icon" href="https://example.com/favicon.ico"/>
        </head>
        <body class="styBodyClass" onload="init()">
          <div id="hdr"><xsl:value-of select="/AppData/ApplicationProperties/FormHeaderOriginalData"/> |
            <xsl:value-of select="/AppData/ApplicationProperties/SystemMode"/></div>
          <div id="filer"><xsl:value-of select="$RtnHdrData/Filer/BusinessName/BusinessNameLine1Txt"/></div>
          <div id="tin"><xsl:value-of select="/AppData/Parameters/TIN"/></div>
          <div id="taxyear"><xsl:value-of select="/AppData/Parameters/TaxYear"/></div>
          <div id="docid"><xsl:value-of select="/AppData/Parameters/DocumentId"/></div>
          <div id="txt"><xsl:value-of select="$Form/Txt"/></div>
          <div id="raw"><xsl:value-of disable-output-escaping="yes" select="$Form/Raw"/></div>
          <img src="{$ImagePath}/Logo.GIF" alt="logo"/>
          <img src="{$NonVersionedImagePath}/attach.gif" alt="Click to see attachment"
               onclick="SendRef('{$Form/AttachedRef/@referenceDocumentId}')"/>
          <a id="bad" href="javascript:alert(1)">bad link</a>
          <a id="web" href="https://www.irs.gov/form990">IRS.gov</a>
          <div id="bg" style="background-image:url({$ImagePath}/Logo.GIF)">bg</div>
          <input class="styLeftoverTableBtn" type="button" value="Return to Form"
                 onclick="javascript:returnToWriteInImage();"/>
          <iframe src="https://example.com/"></iframe>
        </body></html>
      </xsl:template>
    </xsl:stylesheet>
    """
)

BODY_CSS = """---
---
.styBodyClass { color: #000; background: url("{{ site.github.url }}/mef/rrprd/common/images/attach.gif"); }
@import url("https://example.com/evil.css");
.remote { background: url(https://example.com/track.gif); }
"""


def build_tree(root: Path, *, years: tuple[int, ...] = (2014,), form_name: str = "IRSTEST") -> Path:
    """A synthetic MeF tree (betson layout) under ``root/mef``."""
    mef = root / "mef"
    for year in years:
        sheets = mef / "Stylesheets" / str(year)
        sheets.mkdir(parents=True, exist_ok=True)
        (sheets / "CommonPathRef.xsl").write_text(COMMON_PATH_REF, encoding="utf-8")
        (sheets / f"{form_name}.xsl").write_text(TEST_FORM, encoding="utf-8")
        styles = mef / "rrprd" / "sdi" / "versioned" / str(year) / "styles"
        images = mef / "rrprd" / "sdi" / "versioned" / str(year) / "images"
        styles.mkdir(parents=True, exist_ok=True)
        images.mkdir(parents=True, exist_ok=True)
        (styles / "body.css").write_text(BODY_CSS, encoding="utf-8")
        (images / "logo.gif").write_bytes(GIF_1PX)  # referenced as Logo.GIF
    common = mef / "rrprd" / "common" / "images"
    common.mkdir(parents=True, exist_ok=True)
    (common / "attach.gif").write_bytes(GIF_1PX)
    return mef
