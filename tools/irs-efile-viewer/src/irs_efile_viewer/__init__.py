"""Render IRS Modernized e-File (MeF) XML returns as the IRS forms they were filed on.

    from irs_efile_viewer import MefStore, Renderer, parse_return

    ret = parse_return(open("201541349349307794_public.xml", "rb").read(),
                       source_name="201541349349307794_public.xml")
    Renderer(MefStore.locate()).render_all(ret).write("out/")
"""

from .efile import Document, EfileError, EfileReturn, parse_return
from .mef import MefError, MefStore
from .render import Renderer, RenderError, Rendering, build_envelope

__all__ = [
    "Document",
    "EfileError",
    "EfileReturn",
    "MefError",
    "MefStore",
    "RenderError",
    "Renderer",
    "Rendering",
    "build_envelope",
    "parse_return",
]

__version__ = "1.0.0"
